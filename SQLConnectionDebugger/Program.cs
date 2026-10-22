using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.SqlClient;

namespace SQLConnectionDebugger;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args is ["--help"] or ["-h"])
        {
            Console.WriteLine("""
                SQL Connection Debugger - Entra interactive MFA
                Usage: dotnet run --project SQLConnectionDebugger -- [--no-probe] [--device-code] [--log <path>]

                Prompts for a TCP server (host or host,port), database, and Entra username.
                Default port: 1433. Named instances require an explicit TCP port.
                Performs a separate, unauthenticated PRELOGIN probe, then a traced SQL login.
                --no-probe   Skip the separate unauthenticated PRELOGIN probe.
                --log       Log destination (default: yyyy-MM-dd HHmmss.txt beside the executable).
                --device-code  Show a code to sign in manually if the browser does not open.
                Ctrl+C cancels the operation. No passwords or access tokens are requested.
                """);
            return 0;
        }

        try
        {
            var options = Options.Parse(args);
            var endpoint = ServerEndpoint.Parse(Prompt("Server name (host or host,port)"));
            var database = Prompt("Database name");
            var username = Prompt("Entra user name (user@domain)");
            using var log = new DiagnosticLog(options.LogPath, username);
            using var cancellation = new CancellationTokenSource();
            ConsoleCancelEventHandler cancelHandler = (_, e) =>
            {
                e.Cancel = true;
                cancellation.Cancel();
            };
            Console.CancelKeyPress += cancelHandler;
            try
            {
                return await RunAsync(endpoint, database, username, options, log, cancellation.Token);
            }
            finally
            {
                Console.CancelKeyPress -= cancelHandler;
                log.Dispose();
                LogViewer.Open(log.Path);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunAsync(ServerEndpoint endpoint, string database, string username,
        Options options, DiagnosticLog log, CancellationToken cancellationToken)
    {
        log.Write("START", $"SQL Connection Debugger; .NET {Environment.Version}; SqlClient {typeof(SqlConnection).Assembly.GetName().Version}");
        log.Write("LOG", $"Diagnostic file: {log.Path}");
        log.Write("PRIVACY", "Username is redacted. Logs contain server names, database names, IP addresses, and connection IDs. Review before sharing.");
        var authentication = options.DeviceCode
            ? SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow
            : SqlAuthenticationMethod.ActiveDirectoryInteractive;
        log.Write("CONFIG", $"Server={endpoint.DataSource}; Database={database}; Authentication={authentication}; Encrypt=Mandatory; TrustServerCertificate=False; Pooling=False; ConnectRetryCount=0; MARS=False");
        log.Write("NOTE", "PRELOGIN options below come from a SEPARATE probe, not the authenticated driver's connection. Driver events are textual diagnostics, not a wire capture.");

        // This must be set before SqlClient initializes its networking implementation on Windows.
        AppContext.SetSwitch("Switch.Microsoft.Data.SqlClient.UseManagedNetworkingOnWindows", true);
        using var trace = new ConnectionTraceListener(log);
        using var authProvider = new BrowserAuthenticationProvider(log, options.DeviceCode, cancellationToken);
        var previousProvider = SqlAuthenticationProvider.GetProvider(authentication);
        try
        {
            if (!SqlAuthenticationProvider.SetProvider(authentication, authProvider))
            {
                throw new InvalidOperationException("SqlClient rejected the explicit authentication provider.");
            }
            if (options.Probe)
            {
                try
                {
                    await PreloginProbe.RunAsync(endpoint, log, TimeSpan.FromSeconds(10), cancellationToken);
                }
                catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException
                    or InvalidDataException or OperationCanceledException)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    log.Write("PROBE FAILED", $"{ex.GetType().Name}: {ex.Message}. Continuing with the independent SqlClient login; the probe is not a login verdict.");
                }
            }

            var builder = new SqlConnectionStringBuilder
            {
                DataSource = endpoint.DataSource,
                InitialCatalog = database,
                UserID = username,
                Authentication = authentication,
                Encrypt = SqlConnectionEncryptOption.Mandatory,
                TrustServerCertificate = false,
                Pooling = false,
                ConnectRetryCount = 0,
                ConnectTimeout = 360,
                MultipleActiveResultSets = false,
                ApplicationName = "SQLConnectionDebugger"
            };

            await using var connection = new SqlConnection(builder.ConnectionString);
            connection.InfoMessage += (_, e) => log.Write("SQL INFO", e.Message);
            connection.StateChange += (_, e) => log.Write("STATE", $"{e.OriginalState} -> {e.CurrentState}");
            log.Write("CONNECT", "Opening the real SQL connection. Watch DRIVER/NET events for DNS, TCP, PRELOGIN, TLS, LOGIN7/FedAuth, and routing.");
            log.Write("MFA", options.DeviceCode
                ? "Wait for the verification URL/code on the console, then complete sign-in manually. Codes are not stored in the diagnostic file."
                : "Explicit system-browser sign-in is enabled. AUTH PREPARING / AUTH HTTP / AUTH BROWSER show exactly how far sign-in gets. Tenant policy decides whether MFA is required.");
            var timer = Stopwatch.StartNew();
            await connection.OpenAsync(cancellationToken);
            trace.ThrowIfFailed();
            log.Write("CONNECTED", $"Opened in {timer.Elapsed.TotalSeconds:F2}s; ClientConnectionId={connection.ClientConnectionId}; ServerVersion={connection.ServerVersion}; Database={connection.Database}");
            log.Write("ROUTING", "A routing ENVCHANGE is decoded by SqlClient after TLS decryption. 'Received routing info' followed by a new SNI TCP handle identifies a redirect; subsequent DRIVER/NET events trace that destination and port. No redirect is also a valid outcome.");
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1";
            command.CommandTimeout = 30;
            log.Write("QUERY", "Sending SELECT 1 on the authenticated connection.");
            var result = await command.ExecuteScalarAsync(cancellationToken);
            trace.ThrowIfFailed();
            if (result is not int value || value != 1)
            {
                log.Write("FAIL", $"SELECT 1 returned an unexpected value: {Convert.ToString(result, CultureInfo.InvariantCulture)}");
                return 1;
            }
            log.Write("SUCCESS", $"SELECT 1 returned 1; ClientConnectionId={connection.ClientConnectionId}");
            return 0;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            log.Write("CANCELLED", "Cancelled by the user.");
            return 2;
        }
        catch (SqlException ex)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                log.Write("CANCELLED", "Connection/authentication cancelled by the user.");
                return 2;
            }
            log.Write("SQL FAILURE", $"ClientConnectionId={ex.ClientConnectionId}; {ex.Message}");
            foreach (SqlError error in ex.Errors)
            {
                log.Write("SQL ERROR", $"Number={error.Number}; State={error.State}; Class={error.Class}; Server={error.Server}; Message={error.Message}");
            }
            return 1;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            log.Write("FAILURE", $"{ex.GetType().FullName}: {ex.Message}");
            for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
            {
                log.Write("INNER", $"{inner.GetType().FullName}: {inner.Message}");
            }
            return 1;
        }
        finally
        {
            if (previousProvider is not null && !SqlAuthenticationProvider.SetProvider(authentication, previousProvider))
            {
                throw new InvalidOperationException("Could not restore SqlClient's previous authentication provider.");
            }
        }
    }

    private static string Prompt(string label)
    {
        while (true)
        {
            Console.Write($"{label}: ");
            var value = Console.ReadLine() ?? throw new IOException("Input ended before all connection details were supplied.");
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
            Console.Error.WriteLine("A value is required.");
        }
    }
}

internal sealed record Options(bool Probe, string LogPath, bool DeviceCode = false)
{
    public static Options Parse(string[] args)
    {
        var probe = true;
        var deviceCode = false;
        var path = System.IO.Path.Combine(AppContext.BaseDirectory,
            DateTime.Now.ToString("yyyy-MM-dd HHmmss", CultureInfo.InvariantCulture) + ".txt");
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--no-probe":
                    probe = false;
                    break;
                case "--device-code":
                    deviceCode = true;
                    break;
                case "--log" when i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal):
                    path = args[++i];
                    break;
                default:
                    throw new ArgumentException($"Unknown or incomplete option '{args[i]}'. Use --help.");
            }
        }
        return new Options(probe, path, deviceCode);
    }
}
