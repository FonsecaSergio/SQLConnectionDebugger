using Xunit;

namespace SQLConnectionDebugger.Tests;

public sealed class LogViewerTests
{
    [Fact]
    public void NotepadReceivesTimestampedLogAsOneArgument()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "2026-10-22 101138.txt");
        var startInfo = LogViewer.CreateStartInfo(path);
        Assert.Equal("notepad.exe", Path.GetFileName(startInfo.FileName));
        Assert.True(Path.IsPathFullyQualified(startInfo.FileName));
        Assert.False(startInfo.UseShellExecute);
        Assert.Equal(path, Assert.Single(startInfo.ArgumentList));
    }
}
