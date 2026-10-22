using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace SQLConnectionDebugger;

internal static class PreloginProbe
{
    private const int MaxMessageSize = 65535;

    public static async Task RunAsync(ServerEndpoint endpoint, DiagnosticLog log, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var token = deadline.Token;
        using var client = new TcpClient();
        log.Write("PROBE", $"Separate unauthenticated TCP connection to {endpoint.Host}:{endpoint.Port}; timeout={timeout.TotalSeconds}s. No LOGIN7, credentials, or tokens will be sent.");
        await client.ConnectAsync(endpoint.Host, endpoint.Port, token);
        log.Write("PROBE TCP", $"Local={client.Client.LocalEndPoint}; Remote={client.Client.RemoteEndPoint}");
        await using var stream = client.GetStream();
        var packet = BuildRequest();
        log.Write("PROBE SEND", $"TDS PRELOGIN type=0x12; EOM=1; length={packet.Length}; packetId=1; hex={Convert.ToHexString(packet)}");
        foreach (var option in DecodeOptions(packet.AsSpan(8)))
        {
            log.Write("PROBE OPTION SENT", option);
        }
        await stream.WriteAsync(packet, token);
        var response = await ReadResponseAsync(stream, log, token);
        foreach (var option in DecodeOptions(response))
        {
            log.Write("PROBE OPTION RECEIVED", option);
        }
        log.Write("PROBE", "PRELOGIN response decoded; closing this probe before TLS/login. Azure SQL/Synapse routing arrives later during the real login, not in PRELOGIN.");
    }

    internal static byte[] BuildRequest()
    {
        // TDS 7.x PRELOGIN: VERSION, ENCRYPTION, INSTOPT, MARS, FEDAUTHREQUIRED.
        (byte Id, byte[] Value)[] options =
        [
            (0x00, [1, 0, 0, 0, 0, 0]),
            (0x01, [0x01]),
            (0x02, [0x00]),
            (0x04, [0x00]),
            (0x06, [0x01])
        ];
        var tableSize = options.Length * 5 + 1;
        var packet = new byte[8 + tableSize + options.Sum(option => option.Value.Length)];
        packet[0] = 0x12;
        packet[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), checked((ushort)packet.Length));
        packet[6] = 1;
        var position = 8;
        var offset = tableSize;
        foreach (var (id, value) in options)
        {
            packet[position] = id;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(position + 1), (ushort)offset);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(position + 3), (ushort)value.Length);
            value.CopyTo(packet, 8 + offset);
            position += 5;
            offset += value.Length;
        }
        packet[position] = 0xFF;
        return packet;
    }

    internal static async Task<byte[]> ReadResponseAsync(Stream stream, DiagnosticLog log, CancellationToken token)
    {
        using var message = new MemoryStream();
        var header = new byte[8];
        var packets = 0;
        while (true)
        {
            await stream.ReadExactlyAsync(header, token);
            var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
            if (header[0] != 0x04 || length < 8)
            {
                throw new InvalidDataException($"Invalid PRELOGIN response header: type=0x{header[0]:X2}; length={length}. Expected a TDS response (0x04), not TLS-first traffic.");
            }
            if (++packets > 256 || message.Length + length - 8 > MaxMessageSize)
            {
                throw new InvalidDataException("PRELOGIN response exceeded the packet/message size limit.");
            }
            var payload = new byte[length - 8];
            await stream.ReadExactlyAsync(payload, token);
            log.Write("PROBE RECEIVE", $"TDS response type=0x04; status=0x{header[1]:X2}; length={length}; packetId={header[6]}; header={Convert.ToHexString(header)}; payload={Convert.ToHexString(payload)}");
            message.Write(payload);
            if ((header[1] & 1) != 0)
            {
                return message.ToArray();
            }
        }
    }

    internal static IReadOnlyList<string> DecodeOptions(ReadOnlySpan<byte> payload)
    {
        var entries = new List<(byte Id, int Offset, int Length)>();
        var position = 0;
        var terminated = false;
        while (position < payload.Length)
        {
            var id = payload[position++];
            if (id == 0xFF)
            {
                terminated = true;
                break;
            }
            if (payload.Length - position < 4)
            {
                throw new InvalidDataException("Truncated PRELOGIN option table.");
            }
            var offset = BinaryPrimitives.ReadUInt16BigEndian(payload[position..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(payload[(position + 2)..]);
            if (entries.Any(entry => entry.Id == id))
            {
                throw new InvalidDataException($"Duplicate PRELOGIN option 0x{id:X2}.");
            }
            entries.Add((id, offset, length));
            position += 4;
        }
        if (!terminated)
        {
            throw new InvalidDataException("Missing PRELOGIN option-table terminator.");
        }
        var result = new List<string>();
        foreach (var (id, offset, length) in entries)
        {
            if (offset < position || offset > payload.Length || length > payload.Length - offset)
            {
                throw new InvalidDataException($"PRELOGIN option 0x{id:X2} points outside its data region.");
            }
            var value = payload.Slice(offset, length);
            var description = DescribeOption(id, value);
            result.Add($"token=0x{id:X2}; offset={offset}; length={length}; {description}; hex={Convert.ToHexString(value)}");
        }
        return result;
    }

    private static string DescribeOption(byte id, ReadOnlySpan<byte> value) => id switch
    {
        0x00 when value.Length == 6 => $"VERSION={value[0]}.{value[1]}.{BinaryPrimitives.ReadUInt16BigEndian(value[2..])}.{BinaryPrimitives.ReadUInt16LittleEndian(value[4..])}",
        0x01 when value.Length == 1 => $"ENCRYPTION={value[0] switch { 0 => "OFF (login-only encryption possible)", 1 => "ON", 2 => "NOT_SUPPORTED", 3 => "REQUIRED", _ => "UNKNOWN" }}",
        0x02 => $"INSTOPT={Encoding.ASCII.GetString(value).TrimEnd('\0')}",
        0x03 when value.Length == 4 => $"THREADID={BinaryPrimitives.ReadUInt32BigEndian(value)}",
        0x04 when value.Length == 1 => $"MARS={value[0]}",
        0x05 => "TRACEID",
        0x06 when value.Length == 1 => $"FEDAUTHREQUIRED={value[0]}",
        0x07 => "NONCEOPT",
        _ => $"UNKNOWN_OR_INVALID_OPTION=0x{id:X2}"
    };
}
