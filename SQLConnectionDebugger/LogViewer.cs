using System.ComponentModel;
using System.Diagnostics;

namespace SQLConnectionDebugger;

internal static class LogViewer
{
    public static void Open(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine($"Notepad is only available on Windows. Diagnostic log: {path}");
            return;
        }
        try
        {
            using var process = Process.Start(CreateStartInfo(path));
            if (process is null)
            {
                Console.Error.WriteLine($"Could not start Notepad. Open the diagnostic log manually: {path}");
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            Console.Error.WriteLine($"Could not open the log in Notepad: {ex.Message}. Diagnostic log: {path}");
        }
    }

    internal static ProcessStartInfo CreateStartInfo(string path)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe"),
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add(Path.GetFullPath(path));
        return startInfo;
    }
}
