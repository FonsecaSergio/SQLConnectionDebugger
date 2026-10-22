using System.Diagnostics.Tracing;
using System.Globalization;

namespace SQLConnectionDebugger;

internal sealed class ConnectionTraceListener : EventListener
{
    // Exclude binary dumps and StateDump: these can expose login material and tokens.
    internal const EventKeywords SqlKeywords = (EventKeywords)(2 | 4 | 128 | 512 | 2048 | 4096);
    private DiagnosticLog? _log;
    private long _eventCount;
    private Exception? _failure;

    public ConnectionTraceListener(DiagnosticLog log)
    {
        _log = log;
        // EventListener's base constructor can discover sources before _log is assigned.
        foreach (var source in EventSource.GetSources())
        {
            EnableSource(source);
        }
    }

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        if (_log is not null)
        {
            EnableSource(eventSource);
        }
    }

    private void EnableSource(EventSource source)
    {
        if (source.Name == "Microsoft.Data.SqlClient.EventSource")
        {
            EnableEvents(source, EventLevel.Verbose, SqlKeywords);
        }
        else if (source.Name is "System.Net.NameResolution" or "System.Net.Sockets" or "System.Net.Security")
        {
            EnableEvents(source, EventLevel.Verbose, EventKeywords.All);
        }
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        var log = _log;
        if (log is null)
        {
            return;
        }
        var driver = eventData.EventSource.Name == "Microsoft.Data.SqlClient.EventSource";
        if (driver && (eventData.Keywords & (EventKeywords)(256 | 1024)) != 0)
        {
            return;
        }
        var payload = eventData.Payload;
        var fields = new List<string>();
        if (payload is not null)
        {
            for (var i = 0; i < payload.Count; i++)
            {
                var name = eventData.PayloadNames is { } names && i < names.Count ? names[i] : $"arg{i}";
                var value = payload[i] is byte[] ? "<binary omitted>" : Convert.ToString(payload[i], CultureInfo.InvariantCulture);
                fields.Add($"{name}={value}");
            }
        }
        var sequence = Interlocked.Increment(ref _eventCount);
        var details = string.Join(" | ", fields);
        var category = driver ? ClassifyDriverMessage(details) : "NET";
        try
        {
            log.Write(category,
                $"#{sequence} {eventData.EventSource.Name}/{eventData.EventName ?? eventData.EventId.ToString(CultureInfo.InvariantCulture)} activity={eventData.ActivityId} {details}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // EventSource otherwise swallows listener failures, leaving an incomplete success log.
            if (Interlocked.CompareExchange(ref _failure, ex, null) is null)
            {
                Console.Error.WriteLine($"TRACE LOG FAILURE: {ex.Message}");
            }
        }
    }

    public void ThrowIfFailed()
    {
        if (_failure is { } error)
        {
            throw new IOException("Connection trace could not be written completely.", error);
        }
    }

    internal static string ClassifyDriverMessage(string message)
    {
        if (message.Contains("Received routing info", StringComparison.OrdinalIgnoreCase))
        {
            return "REDIRECT";
        }
        if (message.Contains("Connecting to serverName", StringComparison.OrdinalIgnoreCase))
        {
            return "TCP CONNECT";
        }
        if (message.Contains("prelogin", StringComparison.OrdinalIgnoreCase))
        {
            return "PRELOGIN";
        }
        return "DRIVER";
    }
}
