using System.Text;
using System.Text.RegularExpressions;

namespace SQLConnectionDebugger;

internal sealed partial class DiagnosticLog : IDisposable
{
    private readonly object _gate = new();
    private readonly StreamWriter _writer;
    private readonly string _username;

    public string Path { get; }

    public DiagnosticLog(string path, string username)
    {
        Path = System.IO.Path.GetFullPath(path);
        _username = username;
        _writer = new StreamWriter(new FileStream(Path, FileMode.CreateNew, FileAccess.Write, FileShare.Read), new UTF8Encoding(false))
        {
            AutoFlush = true
        };
    }

    public void Write(string category, string message)
    {
        var line = $"{DateTimeOffset.UtcNow:O} [{category}] {Redact(message, _username)}";
        lock (_gate)
        {
            Console.WriteLine(line);
            _writer.WriteLine(line);
        }
    }

    internal static string Redact(string text, string username)
    {
        if (username.Length > 0)
        {
            text = text.Replace(username, "<user>", StringComparison.OrdinalIgnoreCase);
        }
        text = SecretAssignment().Replace(text, "$1=<redacted>");
        text = BearerToken().Replace(text, "Bearer <redacted>");
        text = Jwt().Replace(text, "<redacted-token>");
        return text.Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
    }

    [GeneratedRegex(@"(?i)\b(password|pwd|access[_ ]?token|refresh[_ ]?token|client_secret)\s*[:=]\s*(""[^""]*""|'[^']*'|[^;\s,]+)")]
    private static partial Regex SecretAssignment();

    [GeneratedRegex(@"(?i)\bBearer\s+[A-Za-z0-9._~+/\-=]+")]
    private static partial Regex BearerToken();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")]
    private static partial Regex Jwt();

    public void Dispose() => _writer.Dispose();
}
