using System.Buffers.Binary;
using System.Diagnostics.Tracing;
using System.Net;
using System.Net.Sockets;
using Microsoft.Data.SqlClient;
using Xunit;

namespace SQLConnectionDebugger.Tests;

public sealed class DebuggerTests
{
    [Theory]
    [InlineData("example.database.windows.net", "example.database.windows.net", 1433)]
    [InlineData("tcp:localhost,1444", "localhost", 1444)]
    [InlineData("127.0.0.1,1", "127.0.0.1", 1)]
    [InlineData("[::1],65535", "::1", 65535)]
    public void EndpointParsesExplicitTcpTargets(string input, string host, int port)
    {
        var endpoint = ServerEndpoint.Parse(input);
        Assert.Equal(host, endpoint.Host);
        Assert.Equal(port, endpoint.Port);
        Assert.StartsWith("tcp:", endpoint.DataSource);
    }

    [Theory]
    [InlineData("")]
    [InlineData("host\\instance")]
    [InlineData("host,0")]
    [InlineData("host,65536")]
    [InlineData("host,-1")]
    [InlineData("host,abc")]
    [InlineData("host,1433,1434")]
    [InlineData("host;Encrypt=false")]
    [InlineData("https://host")]
    public void InvalidEndpointFailsExplicitly(string input) =>
        Assert.Throws<ArgumentException>(() => ServerEndpoint.Parse(input));

    [Fact]
    public void ProbePacketContainsExpectedHeaderAndOptions()
    {
        var packet = PreloginProbe.BuildRequest();
        Assert.Equal(0x12, packet[0]);
        Assert.Equal(1, packet[1]);
        Assert.Equal(packet.Length, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2)));
        Assert.Equal(1, packet[6]);
        var options = PreloginProbe.DecodeOptions(packet.AsSpan(8));
        Assert.Equal(5, options.Count);
        Assert.Contains(options, option => option.Contains("VERSION=1.0.0.0"));
        Assert.Contains(options, option => option.Contains("ENCRYPTION=ON"));
        Assert.Contains(options, option => option.Contains("MARS=0"));
        Assert.Contains(options, option => option.Contains("FEDAUTHREQUIRED=1"));
    }

    [Theory]
    [InlineData(0, "OFF")]
    [InlineData(1, "ON")]
    [InlineData(2, "NOT_SUPPORTED")]
    [InlineData(3, "REQUIRED")]
    [InlineData(255, "UNKNOWN")]
    public void DecodeServerEncryptionResponse(byte encryption, string name)
    {
        byte[] payload = [1, 0, 6, 0, 1, 255, encryption];
        Assert.Contains($"ENCRYPTION={name}", Assert.Single(PreloginProbe.DecodeOptions(payload)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("0100")]
    [InlineData("0100060001")]
    [InlineData("0100000001FF00")]
    [InlineData("0100070001FF00")]
    [InlineData("010006FFFFff00")]
    [InlineData("01000B000101000B0001FF01")]
    public void MalformedPreloginIsRejected(string hex) =>
        Assert.Throws<InvalidDataException>(() => PreloginProbe.DecodeOptions(Convert.FromHexString(hex)));

    [Fact]
    public async Task ResponseReaderReassemblesFragmentedTdsPackets()
    {
        using var file = new TestLog();
        var payload = PreloginProbe.BuildRequest()[8..];
        var packets = ResponsePacket(payload[..5], false).Concat(ResponsePacket(payload[5..], true)).ToArray();
        await using var stream = new FragmentedStream(packets);
        var response = await PreloginProbe.ReadResponseAsync(stream, file.Log, CancellationToken.None);
        Assert.Equal(payload, response);
        Assert.Equal(5, PreloginProbe.DecodeOptions(response).Count);
    }

    [Theory]
    [InlineData("0401000700000100", typeof(InvalidDataException))]
    [InlineData("1201000800000100", typeof(InvalidDataException))]
    [InlineData("040100100000010001", typeof(EndOfStreamException))]
    public async Task InvalidResponseFailsWithProtocolOrEofError(string hex, Type expected)
    {
        using var file = new TestLog();
        using var stream = new MemoryStream(Convert.FromHexString(hex));
        var error = await Record.ExceptionAsync(() =>
            PreloginProbe.ReadResponseAsync(stream, file.Log, CancellationToken.None));
        Assert.NotNull(error);
        Assert.IsType(expected, error);
    }

    [Fact]
    public async Task ProbeUsesRealTcpAndNeverSendsLogin()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = new ServerEndpoint("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port);
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(timeout.Token);
            await using var stream = client.GetStream();
            var request = new byte[PreloginProbe.BuildRequest().Length];
            await stream.ReadExactlyAsync(request, timeout.Token);
            Assert.Equal(PreloginProbe.BuildRequest(), request);
            var response = ResponsePacket(request[8..], true);
            foreach (var value in response)
            {
                await stream.WriteAsync(new byte[] { value }, timeout.Token);
            }
            var extra = new byte[1];
            Assert.Equal(0, await stream.ReadAsync(extra, timeout.Token));
        }, timeout.Token);
        using var file = new TestLog();
        await PreloginProbe.RunAsync(endpoint, file.Log, TimeSpan.FromSeconds(5), timeout.Token);
        await server;
        var text = file.ReadText();
        Assert.Contains("PROBE SEND", text);
        Assert.Contains("PROBE OPTION RECEIVED", text);
        Assert.Contains("FEDAUTHREQUIRED=1", text);
    }

    [Fact]
    public async Task ProbeCancellationIsNotReportedAsSuccess()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = new ServerEndpoint("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port);
        using var file = new TestLog();
        var probe = PreloginProbe.RunAsync(endpoint, file.Log, TimeSpan.FromMilliseconds(100), timeout.Token);
        using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);
    }

    [Fact]
    public async Task RealSqlClientEmitsTcpAndPreloginDiagnostics()
    {
        AppContext.SetSwitch("Switch.Microsoft.Data.SqlClient.UseManagedNetworkingOnWindows", true);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var file = new TestLog();
        using var trace = new ConnectionTraceListener(file.Log);
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(timeout.Token);
            await using var stream = client.GetStream();
            var header = new byte[8];
            await stream.ReadExactlyAsync(header, timeout.Token);
            Assert.Equal(0x12, header[0]);
            var body = new byte[BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2)) - 8];
            await stream.ReadExactlyAsync(body, timeout.Token);
            Assert.NotEmpty(PreloginProbe.DecodeOptions(body));
            // Intentionally close before TLS/FedAuth: no real account or MFA is contacted.
            listener.Stop();
        }, timeout.Token);
        var builder = new SqlConnectionStringBuilder
        {
            DataSource = $"tcp:127.0.0.1,{port}",
            InitialCatalog = "offline-test",
            UserID = "test@example.invalid",
            Authentication = SqlAuthenticationMethod.ActiveDirectoryInteractive,
            Pooling = false,
            ConnectRetryCount = 0,
            ConnectTimeout = 2,
            Encrypt = SqlConnectionEncryptOption.Mandatory
        };
        await using var connection = new SqlConnection(builder.ConnectionString);
        await Assert.ThrowsAsync<SqlException>(() => connection.OpenAsync(timeout.Token));
        await server;
        trace.ThrowIfFailed();
        var text = file.ReadText();
        Assert.Contains("[TCP CONNECT]", text);
        Assert.Contains($"port {port}", text);
        Assert.Contains("Sending prelogin handshake", text);
        Assert.Contains("System.Net.Sockets", text);
        Assert.DoesNotContain("EventSourceMessage", text);
    }

    [Theory]
    [InlineData("Received routing info", "REDIRECT")]
    [InlineData("Connecting to serverName backend and port 11042", "TCP CONNECT")]
    [InlineData("Sending prelogin handshake", "PRELOGIN")]
    [InlineData("Consuming prelogin handshake", "PRELOGIN")]
    [InlineData("SSL enabled successfully", "DRIVER")]
    public void TraceHighlightsActualRoutingAndConnections(string message, string expected) =>
        Assert.Equal(expected, ConnectionTraceListener.ClassifyDriverMessage(message));

    [Fact]
    public void DangerousTraceKeywordsAreDisabled()
    {
        Assert.Equal(0, (long)(ConnectionTraceListener.SqlKeywords & (EventKeywords)(256 | 1024)));
        Assert.NotEqual(0, (long)(ConnectionTraceListener.SqlKeywords & (EventKeywords)2048));
    }

    [Fact]
    public void RedactsCredentialsAndEscapesLogInjection()
    {
        var text = DiagnosticLog.Redact(
            "USER@EXAMPLE.COM password=secret; pwd='has spaces'; Access Token=opaque; refresh_token=refresh; client_secret=\"hidden value\"; Bearer abc.def.ghi eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.signature\r\nforged", "user@example.com");
        Assert.DoesNotContain("USER@EXAMPLE.COM", text);
        foreach (var secret in new[] { "secret;", "has spaces", "opaque", "=refresh;", "hidden value", "abc.def.ghi", "eyJhbGci" })
        {
            Assert.DoesNotContain(secret, text);
        }
        Assert.Contains("<user>", text);
        Assert.Contains("\\r\\nforged", text);
        Assert.DoesNotContain("\n", text);
    }

    [Fact]
    public void OptionsHaveSafeDefaultsAndDoNotOverwriteExistingLogs()
    {
        var defaults = Options.Parse([]);
        Assert.True(defaults.Probe);
        Assert.Equal(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetDirectoryName(defaults.LogPath));
        Assert.Matches(@"^\d{4}-\d{2}-\d{2} \d{6}\.txt$", Path.GetFileName(defaults.LogPath));
        Assert.True(DateTime.TryParseExact(Path.GetFileNameWithoutExtension(defaults.LogPath),
            "yyyy-MM-dd HHmmss", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out var logTime));
        Assert.InRange((DateTime.Now - logTime).TotalSeconds, -1, 5);
        var options = Options.Parse(["--no-probe", "--log", "custom.log"]);
        Assert.False(options.Probe);
        Assert.Equal("custom.log", options.LogPath);
        Assert.Throws<ArgumentException>(() => Options.Parse(["--log"]));
        Assert.Throws<ArgumentException>(() => Options.Parse(["--unknown"]));
        using var file = new TestLog();
        Assert.Throws<IOException>(() => new DiagnosticLog(file.Path, "user"));
    }

    private static byte[] ResponsePacket(byte[] payload, bool endOfMessage)
    {
        var packet = new byte[8 + payload.Length];
        packet[0] = 4;
        packet[1] = endOfMessage ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), checked((ushort)packet.Length));
        packet[6] = 1;
        payload.CopyTo(packet, 8);
        return packet;
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, 1)], cancellationToken);
    }

    private sealed class TestLog : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"sql-debugger-test-{Guid.NewGuid():N}.log");
        public DiagnosticLog Log { get; }

        public TestLog() => Log = new DiagnosticLog(Path, "test@example.invalid");

        public string ReadText()
        {
            using var reader = new StreamReader(new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            return reader.ReadToEnd();
        }

        public void Dispose()
        {
            Log.Dispose();
            File.Delete(Path);
        }
    }
}
