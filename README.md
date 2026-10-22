# SQL Connection Debugger

A .NET 10 console utility for debugging TCP connections to Azure Synapse SQL,
Azure SQL, and SQL Server configured for Microsoft Entra authentication.

## Run

```powershell
dotnet run --project .\SQLConnectionDebugger
```

Enter:

1. **Server**: for example `workspace.sql.azuresynapse.net`,
   `workspace-ondemand.sql.azuresynapse.net`, `server.database.windows.net`, or
   `sqlserver.example.com,1433`. An optional `tcp:` prefix is accepted.
   For named SQL Server instances, find the TCP port and use `host,port`.
2. **Database**: the actual database/pool name, not a URL.
3. **Entra username**: your organizational account, such as `user@contoso.com`.

Complete the explicit system-browser Entra sign-in. This supports MFA; your tenant's
Conditional Access policy determines whether a challenge is required. The
username is a login hint, not a password. The utility never asks for a password.
Interactive sign-in requires a usable desktop/browser environment and access to
Microsoft Entra endpoints. Ordinary on-premises SQL Server must support and be
configured for Entra authentication; this is not SQL-password or Windows auth.

The utility registers an explicit MSAL authentication provider: it requests an
interactive account selection, uses the default system browser (not an embedded
window or Windows broker), and does not attempt silent token-cache authentication.
The browser may open a tab in an existing window. MFA is still controlled by
tenant policy and existing browser sessions, not forced by the utility.

The program opens a fresh, non-pooled connection and executes exactly `SELECT 1`.
Encryption is mandatory and server certificate validation stays enabled.
It does not change server configuration.

```powershell
# Choose the local log destination (existing files are never overwritten).
dotnet run --project .\SQLConnectionDebugger -- --log .\connection.log

# Skip the independent PRELOGIN probe.
dotnet run --project .\SQLConnectionDebugger -- --no-probe

# No browser window, or localhost callback blocked? Use manual device-code login.
dotnet run --project .\SQLConnectionDebugger -- --device-code

dotnet run --project .\SQLConnectionDebugger -- --help
```

Exit codes: **0** = query returned integer 1; **1** = failure; **2** = cancelled
with Ctrl+C during the diagnostic run. Connection timeout is 360 seconds to
allow interactive sign-in; authentication has its own five-minute deadline and
each authentication HTTP request has a 20-second deadline. Command timeout is
30 seconds. Internal driver
connection attempts may still occur even though idle connection recovery is
disabled with `ConnectRetryCount=0`.

### If the sign-in browser does not appear

The new `AUTH` categories distinguish the stages instead of relying on the
driver's potentially misleading `Acquired access token (silent) ... Expiry Time:
null` message. That older driver message does **not** mean a token was acquired.

- `AUTH START` / `AUTH PREPARING`: the provider is starting interactive sign-in.
- `AUTH HTTP SEND` / `AUTH HTTP RESPONSE`: Entra metadata/token requests, with
  method, URL **without its query**, response status, and duration. Headers and
  request/response bodies are never logged.
- `AUTH HTTP CANCELLED` / `AUTH HTTP FAILED`: investigate access to the named
  Entra host, HTTPS proxy/VPN settings, or sign-in cancellation. Metadata is
  fetched **before** browser launch; a blocked metadata request prevents the
  browser from opening at all.
- `AUTH BROWSER`: explicitly asks the OS to launch the default HTTPS browser,
  then waits for MSAL's localhost redirect callback. OS acceptance is not proof
  a visible window appeared.
- `AUTH BROWSER FAILED`: configure a default HTTPS browser or use device code.
- `AUTH TOKEN`: MSAL actually returned a token; only its expiry is recorded.

If `AUTH BROWSER` appears but there is no visible sign-in, check existing browser
windows/tabs. Alternatively rerun with `--device-code`: manually open the
verification URL and enter the code displayed in the console. No browser is
automatically launched in that mode and no localhost callback is needed.
The code is intentionally not written to the diagnostic log. Device-code flow
must be permitted by tenant policy; it is an explicit alternative, not a silent
fallback or a bypass for MFA/Conditional Access. Ctrl+C cancels either mode.

## What the output means

Each line has a UTC timestamp and category, and is written to both the console
and a text file beside the running executable (`AppContext.BaseDirectory`),
named `yyyy-MM-dd HHmmss.txt` using local time (24-hour clock), for example
`2026-10-22 101138.txt`. This includes probe, driver, network, authentication-stage,
query, and error diagnostics. Each entry is flushed immediately.
The working directory does not affect the default location. With `dotnet run`,
the file is in the application's build-output folder beside its executable.
Use `--log <path>` to override the destination. The folder must be writable;
existing files are never overwritten (including two runs started in the same
second: choose a different `--log` path if necessary).
Sensitive authentication URLs, tokens, and device codes remain excluded.
At the end of a diagnostic run (success, failure, or Ctrl+C cancellation), the
file is closed and opened in Windows Notepad before the console program exits.
The program does not wait for Notepad to close. If Notepad cannot start, the
console displays an error and the log path; the connection's exit code is
preserved. Runs that fail before a diagnostic log is created cannot open a log.

### 1. Exact, unauthenticated PRELOGIN probe

`PROBE` is a **separate TCP connection** to the requested server and port. It:

- Logs the actual local and remote socket endpoints.
- Sends a TDS 7.x PRELOGIN packet (`0x12`), with complete header/payload hex.
- Decodes the options sent: probe VERSION `1.0.0.0`, ENCRYPTION `ON`, INSTOPT,
  MARS `0`, and FEDAUTHREQUIRED `1`.
- Reads/reassembles the server's TDS response (`0x04`) and logs the actual
  returned version, encryption, MARS, FedAuth, and any other options.
- Closes **before TLS, LOGIN7, or credentials**. It has a 10-second deadline.

The probe is not the SqlClient connection and does not claim to reproduce its
exact options, client version, or outcome. It cannot authenticate or observe a
login redirect. Failure is logged explicitly, and the actual driver connection
is still attempted. A probe success is not an authenticated login success.
Use `--no-probe` for endpoints that reject a traditional PRELOGIN probe.

### 2. The actual MFA connection

The utility enables managed SqlClient networking **before opening connections**,
including on Windows, and listens to:

- `Microsoft.Data.SqlClient.EventSource`: connection lifecycle, sending/consuming
  PRELOGIN, TLS, login/FedAuth processing, routing ENVCHANGE, packet read/write
  activity, errors, and cleanup.
- `System.Net.NameResolution`: actual DNS activity.
- `System.Net.Sockets`: actual socket connects, including redirected connections.
- `System.Net.Security`: TLS handshake activity/protocol and failures, as exposed
  by .NET. Some events may also correspond to authentication-related TLS.

`PRELOGIN` highlights the driver's own handshake messages.
`REDIRECT` highlights **"Received routing info"**, meaning SqlClient decoded a
server routing ENVCHANGE. The next `TCP CONNECT` driver message identifies the
new **hostname and port**; the following driver/network events trace its DNS,
TCP, PRELOGIN, TLS, and login as well. Connection IDs associate driver operations
with their SNI connection. The driver's older `Routed to` message may name the
*original* server, so use the next `TCP CONNECT`, not that line, as the target.

Not every endpoint redirects: proxy policy, SQL Server, and some Synapse
endpoints may keep the original connection. A redirect is delivered during the
login response, not the PRELOGIN response. Network rules must permit the actual
redirect destination and port shown in the log.

`CONNECTED` includes the client connection ID, server version, and database.
`QUERY` announces the command; `SUCCESS` is emitted only after the returned value
has been checked to be integer 1. SQL failures include error number, severity
(class), state, and client connection ID.

## Visibility and privacy limits

This is driver/protocol diagnostics, **not a packet sniffer or TLS interception
proxy**. Actual login packets, tokens, query data, and routing packets are
encrypted on the wire. SqlClient's textual events describe its processing, but
do not expose every packet field, exact wire bytes, or every negotiated option.
Exact PRELOGIN option values shown by this tool belong only to the labeled probe.
TLS-first/TDS 8.0 (`Encrypt=Strict`) is not used by the authenticated connection;
it uses the broadly compatible `Encrypt=Mandatory` handshake.

For TCP retransmissions, resets, timing, and every encrypted wire packet, collect
an OS packet capture separately (for example, Wireshark or Windows `pktmon`).
Correlate its endpoints/timestamps with this log; a capture alone cannot decode
encrypted routing tokens. Do not disable encryption or certificate validation to
obtain plaintext.

Binary driver dumps and full state dumps are deliberately **not enabled**.
Username, common credential assignments, bearer tokens, and JWT-shaped values
are redacted before writing either destination. This is defense in depth, not a
guarantee that every possible sensitive value from all future driver events is
recognized. Logs still contain database/server names, IPs, tenant/authentication
metadata, SQL errors, and connection IDs. Store locally, review before sharing,
and delete when no longer needed. HTTP bodies and MSAL verbose/PII logs are not
enabled. Authentication HTTP lifecycle logging excludes headers, query strings,
bodies, authorization URLs, and device codes. No log is uploaded by this utility.

SqlClient 6.1 is the LTS driver line and includes interactive Entra support.
The explicit patched `System.Security.Cryptography.Pkcs` reference overrides the
older transitive version brought in by that driver's authentication dependency.

## Build and offline tests

### Publish a single EXE (Windows x64)

```powershell
dotnet publish .\SQLConnectionDebugger\SQLConnectionDebugger.csproj --configuration Release --runtime win-x64
```

Distribute only `SQLConnectionDebugger\bin\Release\net10.0\win-x64\publish\SQLConnectionDebugger.exe`.
The EXE bundles the managed dependencies, native libraries, debug symbols, and
.NET runtime; the destination computer does not need .NET installed. Native
libraries are extracted to the user's temporary directory when needed at runtime.
Trimming is not enabled, preserving SqlClient and authentication behavior.

```powershell
.\SQLConnectionDebugger\bin\Release\net10.0\win-x64\publish\SQLConnectionDebugger.exe --help
```

Use `--runtime win-arm64` instead for Windows ARM64 (the output path changes
accordingly). A normal `dotnet build` still generates intermediate DLLs and
dependency files for development and tests; use the **publish** folder for the
single-file application.

### Development build and tests

```powershell
dotnet build .\SQLConnectionDebugger.sln --configuration Release
dotnet test .\SQLConnectionDebugger.Tests\SQLConnectionDebugger.Tests.csproj --configuration Release
```

Tests validate packet layout/decoding, malformed/truncated responses, fragmented
reads, endpoint validation, cancellation, redaction, log safety, and real loopback
TCP exchanges. A real SqlClient connection to a local fake endpoint verifies that
managed TCP and PRELOGIN events are emitted; it stops before TLS/authentication.
Authentication tests exercise MSAL with fake metadata responses, verify that
its real interactive flow invokes the explicit browser callback, and check HTTP
logging privacy, cancellation, browser launch errors, and device-code selection.
Tests do not contact a real database or perform MFA. Live end-to-end
authentication, redirect, and query verification require your endpoint/account.

References:

- [SqlClient EventSource tracing](https://learn.microsoft.com/sql/connect/ado-net/enable-eventsource-tracing)
- [Microsoft Entra authentication in SqlClient](https://learn.microsoft.com/sql/connect/ado-net/sql/azure-active-directory-authentication)
- [MS-TDS protocol specification](https://learn.microsoft.com/openspecs/windows_protocols/ms-tds/)
