using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Data.SqlClient;
using Microsoft.Identity.Client;

namespace SQLConnectionDebugger;

internal sealed class BrowserAuthenticationProvider : SqlAuthenticationProvider, IDisposable
{
    // Same public application ID as SqlClient 6.1.7 (ActiveDirectoryAuthentication.AdoClientId).
    internal const string ClientId = "2fd908ad-0664-4344-b9be-cd3e8b574c38";
    private readonly DiagnosticLog _log;
    private readonly CancellationToken _cancellationToken;
    private readonly bool _deviceCode;
    private readonly Action<Uri> _launchBrowser;
    private readonly AuthenticationHttpClientFactory _http;

    public BrowserAuthenticationProvider(DiagnosticLog log, bool deviceCode, CancellationToken cancellationToken,
        Action<Uri>? launchBrowser = null, HttpMessageHandler? httpHandler = null)
    {
        _log = log;
        _deviceCode = deviceCode;
        _cancellationToken = cancellationToken;
        _launchBrowser = launchBrowser ?? LaunchSystemBrowser;
        _http = new AuthenticationHttpClientFactory(log, httpHandler);
    }

    public override bool IsSupported(SqlAuthenticationMethod authenticationMethod) =>
        authenticationMethod == (_deviceCode
            ? SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow
            : SqlAuthenticationMethod.ActiveDirectoryInteractive);

    public override Task<SqlAuthenticationToken> AcquireTokenAsync(SqlAuthenticationParameters parameters) =>
        AcquireAsync(parameters.Authority, parameters.Resource, parameters.UserId, parameters.ConnectionId);

    internal async Task<SqlAuthenticationToken> AcquireAsync(string authority, string resource, string username,
        Guid connectionId)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(5));
        var token = deadline.Token;
        var browserRequested = false;
        try
        {
            _log.Write("AUTH START", $"Explicit {(_deviceCode ? "device-code" : "system-browser")} sign-in; ClientConnectionId={connectionId}; timeout=5 minutes. No silent token-cache attempt or Windows broker is used.");
            var app = PublicClientApplicationBuilder.Create(ClientId)
                .WithAuthority(authority)
                .WithRedirectUri("http://localhost")
                .WithHttpClientFactory(_http)
                .Build();
            var scopes = new[] { resource.TrimEnd('/') + "/.default" };
            AuthenticationResult result;
            if (_deviceCode)
            {
                result = await app.AcquireTokenWithDeviceCode(scopes, code =>
                {
                    _log.Write("AUTH DEVICE CODE", "Verification instructions are displayed on the console only, not written to the log. Tenant policy may prohibit device-code flow.");
                    Console.WriteLine(code.Message);
                    return Task.CompletedTask;
                }).WithCorrelationId(connectionId).ExecuteAsync(token);
            }
            else
            {
                _log.Write("AUTH PREPARING", "Fetching Entra metadata before launching the browser. Each authentication HTTP request has a 20-second deadline; watch AUTH HTTP entries.");
                result = await app.AcquireTokenInteractive(scopes)
                    .WithLoginHint(username)
                    .WithPrompt(Microsoft.Identity.Client.Prompt.SelectAccount)
                    .WithCorrelationId(connectionId)
                    .WithUseEmbeddedWebView(false)
                    .WithSystemWebViewOptions(new SystemWebViewOptions
                    {
                        OpenBrowserAsync = uri =>
                        {
                            browserRequested = true;
                            return OpenBrowserAsync(uri, token);
                        }
                    })
                    .ExecuteAsync(token);
            }
            _log.Write("AUTH TOKEN", $"Entra returned a token; expires={result.ExpiresOn:O}. Token contents are not logged.");
            return new SqlAuthenticationToken(result.AccessToken, result.ExpiresOn);
        }
        catch (OperationCanceledException) when (_cancellationToken.IsCancellationRequested)
        {
            _log.Write("AUTH CANCELLED", "Authentication cancelled by Ctrl+C.");
            throw;
        }
        catch (OperationCanceledException)
        {
            _log.Write("AUTH TIMEOUT", $"Authentication exceeded its deadline. Browser launch requested={browserRequested}. Check AUTH HTTP for a stalled request; use --device-code if browser return to localhost is blocked.");
            throw;
        }
        catch (MsalException ex)
        {
            _log.Write("AUTH ERROR", $"MSAL error={ex.ErrorCode}; correlation={ex.CorrelationId}; Browser launch requested={browserRequested}. See AUTH HTTP and AUTH BROWSER events. Use --device-code to avoid browser launching and the localhost callback.");
            throw;
        }
    }

    internal Task OpenBrowserAsync(Uri uri, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("Refusing to launch a non-HTTPS authentication URL.");
        }
        _log.Write("AUTH BROWSER", $"Requesting the default system browser for HTTPS host {uri.Host}. Authorization URL/query is intentionally omitted.");
        try
        {
            _launchBrowser(uri);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            _log.Write("AUTH BROWSER FAILED", $"Browser launch failed ({ex.GetType().Name}). Check the default HTTPS browser association, or rerun with --device-code.");
            throw new InvalidOperationException("Could not launch the system browser. Configure a default HTTPS browser or use --device-code.", ex);
        }
        _log.Write("AUTH BROWSER", "Browser launch request accepted by the OS (not proof a visible window opened). Complete sign-in in the browser; waiting for MSAL's localhost callback. If no window appears, use --device-code.");
        return Task.CompletedTask;
    }

    private static void LaunchSystemBrowser(Uri uri)
    {
        using var process = Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    }

    public void Dispose() => _http.Dispose();
}

internal sealed class AuthenticationHttpClientFactory : IMsalHttpClientFactory, IDisposable
{
    private readonly HttpClient _client;

    public AuthenticationHttpClientFactory(DiagnosticLog log, HttpMessageHandler? handler = null)
    {
        _client = new HttpClient(new AuthenticationHttpHandler(log, handler ?? new HttpClientHandler()))
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
    }

    public HttpClient GetHttpClient() => _client;

    public void Dispose() => _client.Dispose();
}

internal sealed class AuthenticationHttpHandler(DiagnosticLog log, HttpMessageHandler inner) : DelegatingHandler(inner)
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Never log HTTP headers, query strings, bodies, or exception messages containing URLs.
        var target = request.RequestUri?.GetLeftPart(UriPartial.Path) ?? "<missing URI>";
        var timer = Stopwatch.StartNew();
        log.Write("AUTH HTTP SEND", $"{request.Method} {target}; headers/query/body omitted");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            var response = await base.SendAsync(request, deadline.Token);
            log.Write("AUTH HTTP RESPONSE", $"{request.Method} {target}; HTTP {(int)response.StatusCode}; elapsed={timer.Elapsed.TotalSeconds:F2}s");
            return response;
        }
        catch (OperationCanceledException)
        {
            log.Write("AUTH HTTP CANCELLED", $"{request.Method} {target}; elapsed={timer.Elapsed.TotalSeconds:F2}s; request timeout or sign-in cancellation. Check Entra reachability/proxy/VPN.");
            throw;
        }
        catch (HttpRequestException ex)
        {
            log.Write("AUTH HTTP FAILED", $"{request.Method} {target}; error={ex.HttpRequestError}; elapsed={timer.Elapsed.TotalSeconds:F2}s");
            throw;
        }
    }
}
