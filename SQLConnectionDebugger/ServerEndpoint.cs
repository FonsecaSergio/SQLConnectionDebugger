using System.Globalization;
using System.Net;

namespace SQLConnectionDebugger;

internal sealed record ServerEndpoint(string Host, int Port)
{
    public string DataSource => $"tcp:{(Host.Contains(':') ? $"[{Host}]" : Host)},{Port}";

    public static ServerEndpoint Parse(string input)
    {
        var value = input.Trim();
        if (value.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase))
        {
            value = value[4..];
        }
        var parts = value.Split(',');
        if (parts.Length > 2 || parts[0].Length == 0)
        {
            throw new ArgumentException("Use a TCP hostname or IP address, optionally followed by ,port.");
        }
        var host = parts[0].Trim();
        if (host.StartsWith('[') && host.EndsWith(']'))
        {
            host = host[1..^1];
        }
        if (Uri.CheckHostName(host) == UriHostNameType.Unknown || host.Any(char.IsWhiteSpace)
            || host.Contains('\\') || host.Contains(';'))
        {
            throw new ArgumentException("Invalid TCP server. For named instances, supply host,port rather than host\\instance.");
        }
        var port = 1433;
        if (parts.Length == 2 && (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out port)
            || port is < IPEndPoint.MinPort + 1 or > IPEndPoint.MaxPort))
        {
            throw new ArgumentException("TCP port must be between 1 and 65535.");
        }
        return new ServerEndpoint(host, port);
    }
}
