using System.ComponentModel;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.Identity.Client;
using Xunit;

namespace SQLConnectionDebugger.Tests;

public sealed class AuthenticationTests
{
    [Fact]
    public async Task BrowserCallbackLaunchesHttpsWithoutLoggingAuthorizationQuery()
    {
        using var file = new TestLog();
        Uri? launched = null;
        using var provider = new BrowserAuthenticationProvider(file.Log, false, CancellationToken.None,
            uri => launched = uri);
        var uri = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?login_hint=private&state=private-state");
        await provider.OpenBrowserAsync(uri, CancellationToken.None);
        Assert.Equal(uri, launched);
        Assert.Contains("Browser launch request accepted", file.ReadText());
        Assert.DoesNotContain("private", file.ReadText());
        Assert.DoesNotContain("login_hint", file.ReadText());
    }

    [Fact]
    public async Task BrowserFailureIsExplicitAndOffersDeviceCode()
    {
        using var file = new TestLog();
        using var provider = new BrowserAuthenticationProvider(file.Log, false, CancellationToken.None,
            _ => throw new Win32Exception("No HTTPS association"));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.OpenBrowserAsync(new Uri("https://login.microsoftonline.com/"), CancellationToken.None));
        Assert.Contains("--device-code", error.Message);
        Assert.Contains("AUTH BROWSER FAILED", file.ReadText());
        Assert.DoesNotContain("launch request accepted", file.ReadText());
    }

    [Theory]
    [InlineData("http://login.microsoftonline.com/")]
    [InlineData("file:///C:/Windows/notepad.exe")]
    public async Task BrowserRejectsNonHttpsUrls(string address)
    {
        using var file = new TestLog();
        var launched = false;
        using var provider = new BrowserAuthenticationProvider(file.Log, false, CancellationToken.None,
            _ => launched = true);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.OpenBrowserAsync(new Uri(address), CancellationToken.None));
        Assert.False(launched);
    }

    [Fact]
    public async Task HttpDiagnosticsExcludeQueryHeadersAndBodies()
    {
        using var file = new TestLog();
        using var factory = new AuthenticationHttpClientFactory(file.Log, new StubHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("private-response-token")
            })));
        using var request = new HttpRequestMessage(HttpMethod.Post,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token?code=private-code")
        {
            Content = new StringContent("private-request-token")
        };
        request.Headers.Add("Authorization", "Bearer private-header-token");
        using var response = await factory.GetHttpClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("AUTH HTTP SEND", file.ReadText());
        Assert.Contains("HTTP 400", file.ReadText());
        Assert.DoesNotContain("private", file.ReadText());
        Assert.Equal(TimeSpan.FromSeconds(20), factory.GetHttpClient().Timeout);
    }

    [Fact]
    public async Task HttpCancellationIsLoggedRatherThanHangingSilently()
    {
        using var file = new TestLog();
        using var cancelled = new CancellationTokenSource();
        using var factory = new AuthenticationHttpClientFactory(file.Log, new StubHandler(async (_, token) =>
        {
            cancelled.Cancel();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            factory.GetHttpClient().GetAsync("https://login.microsoftonline.com/metadata", cancelled.Token));
        Assert.Contains("AUTH HTTP CANCELLED", file.ReadText());
    }

    [Fact]
    public async Task HttpFailureDoesNotLogExceptionUrlOrCredentials()
    {
        using var file = new TestLog();
        using var factory = new AuthenticationHttpClientFactory(file.Log, new StubHandler((_, _) =>
            throw new HttpRequestException("https://login.microsoftonline.com/?secret=private")));
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            factory.GetHttpClient().GetAsync("https://login.microsoftonline.com/metadata"));
        Assert.Contains("AUTH HTTP FAILED", file.ReadText());
        Assert.DoesNotContain("private", file.ReadText());
    }

    [Fact]
    public async Task ActualMsalInteractiveFlowReachesExplicitBrowserCallback()
    {
        using var file = new TestLog();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Uri? launched = null;
        const string authority = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111";
        using var handler = new StubHandler((request, _) => Task.FromResult(MetadataResponse(request, authority)));
        using var provider = new BrowserAuthenticationProvider(file.Log, false, cancellation.Token, uri =>
        {
            launched = uri;
            cancellation.Cancel();
        }, handler);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            provider.AcquireAsync(authority, "https://database.windows.net/", "test@example.invalid", Guid.NewGuid()));
        Assert.NotNull(launched);
        Assert.Equal("https", launched.Scheme);
        Assert.Contains("prompt=select_account", launched.Query);
        Assert.Contains("redirect_uri=http%3A%2F%2Flocalhost", launched.Query, StringComparison.OrdinalIgnoreCase);
        var text = file.ReadText();
        Assert.Contains("AUTH PREPARING", text);
        Assert.Contains("AUTH BROWSER", text);
        Assert.Contains("AUTH CANCELLED", text);
        Assert.DoesNotContain("test@example.invalid", text);
        Assert.DoesNotContain("AUTH TOKEN", text);
    }

    [Fact]
    public async Task ActualMsalDeviceFlowDisplaysInstructionsWithoutLaunchingBrowserOrLoggingCode()
    {
        using var file = new TestLog();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var launched = false;
        const string authority = "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222";
        using var handler = new StubHandler((request, token) =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/devicecode", StringComparison.Ordinal))
            {
                return Task.FromResult(JsonResponse(new
                {
                    device_code = "private-device-code",
                    user_code = "TEST-CODE",
                    verification_uri = "https://microsoft.com/devicelogin",
                    expires_in = 900,
                    interval = 1,
                    message = "Offline test only: private-device-code TEST-CODE"
                }));
            }
            if (path.EndsWith("/token", StringComparison.Ordinal))
            {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
            }
            return Task.FromResult(MetadataResponse(request, authority));
        });
        using var provider = new BrowserAuthenticationProvider(file.Log, true, cancellation.Token,
            _ => launched = true, handler);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            provider.AcquireAsync(authority, "https://database.windows.net/", "test@example.invalid", Guid.NewGuid()));
        Assert.False(launched);
        var text = file.ReadText();
        Assert.Contains("AUTH DEVICE CODE", text);
        Assert.Contains("AUTH CANCELLED", text);
        Assert.DoesNotContain("private-device-code", text);
        Assert.DoesNotContain("TEST-CODE", text);
        Assert.DoesNotContain("AUTH TOKEN", text);
    }

    [Fact]
    public void DeviceCodeIsExplicitOptInAndProviderSupportsOnlySelectedMode()
    {
        Assert.False(Options.Parse([]).DeviceCode);
        Assert.True(Options.Parse(["--device-code"]).DeviceCode);
        using var file = new TestLog();
        using var browser = new BrowserAuthenticationProvider(file.Log, false, CancellationToken.None);
        using var device = new BrowserAuthenticationProvider(file.Log, true, CancellationToken.None);
        Assert.True(browser.IsSupported(SqlAuthenticationMethod.ActiveDirectoryInteractive));
        Assert.False(browser.IsSupported(SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow));
        Assert.True(device.IsSupported(SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow));
        Assert.False(device.IsSupported(SqlAuthenticationMethod.ActiveDirectoryInteractive));
    }

    private static HttpResponseMessage MetadataResponse(HttpRequestMessage request, string authority) =>
        request.RequestUri!.AbsolutePath.Contains("/discovery/instance", StringComparison.Ordinal)
            ? JsonResponse(new
            {
                tenant_discovery_endpoint = authority + "/v2.0/.well-known/openid-configuration",
                metadata = new[]
                {
                    new
                    {
                        preferred_network = "login.microsoftonline.com",
                        preferred_cache = "login.microsoftonline.com",
                        aliases = new[] { "login.microsoftonline.com", "login.windows.net" }
                    }
                }
            })
            : JsonResponse(new
            {
                authorization_endpoint = authority + "/oauth2/v2.0/authorize",
                token_endpoint = authority + "/oauth2/v2.0/token",
                device_authorization_endpoint = authority + "/oauth2/v2.0/devicecode",
                issuer = authority + "/v2.0",
                jwks_uri = authority + "/discovery/v2.0/keys",
                end_session_endpoint = authority + "/oauth2/v2.0/logout"
            });

    private static HttpResponseMessage JsonResponse(object body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
    };

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }

    private sealed class TestLog : IDisposable
    {
        private readonly string _path = Path.Combine(Path.GetTempPath(), $"sql-auth-test-{Guid.NewGuid():N}.log");
        public DiagnosticLog Log { get; }

        public TestLog() => Log = new DiagnosticLog(_path, "test@example.invalid");

        public string ReadText()
        {
            using var reader = new StreamReader(new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            return reader.ReadToEnd();
        }

        public void Dispose()
        {
            Log.Dispose();
            File.Delete(_path);
        }
    }
}
