# TLS Server Certificate Selection

This repository contains a .NET TLS `ClientHello` parser for server certificate selection during the TLS handshake.
The parser is web-server agnostic and can be used by any .NET server to choose a compatible certificate based on the client's advertised capabilities, such as supported signature algorithms.

The types are designed to support TLS 1.2 and TLS 1.3, as defined by [RFC 5246][rfc_5246] and [RFC 8446][rfc_8446].

The repository also includes integration tests that demonstrate this approach with the ASP.NET Core Kestrel web server.

## Background

During the TLS handshake, the client sends information about the server authentication algorithms it supports. A server can use that information to choose a compatible certificate before the handshake completes.

The information relevant to certificate selection is located in different parts of [`ClientHello`][rfc_8446_clienthello], depending on the TLS version:

| TLS Version | Primary Source | Secondary Source |
|:-----------:|----------------|------------------|
| 1.2 | `signature_algorithms` extension | `cipher_suites` field |
| 1.3 | `signature_algorithms_cert` extension | `signature_algorithms` extension |

## How Integration Tests Work

The core parser is web-server agnostic. It parses the TLS record and extracts the `ClientHello` data needed for certificate selection.

The integration tests use Kestrel because it exposes two APIs that make this flow straightforward:

- [TlsClientHelloBytesCallback][ms_learn_tlsclienthellobytescallback], which is invoked when a `ClientHello` is received and provides the raw TLS record bytes.
- [ServerCertificateSelector][ms_learn_servercertificateselector], which is invoked before TLS negotiation completes and returns the certificate to use.

[`TlsClientHelloParser`][code_TlsClientHelloParser] can then be used in a flow like this:

### Flow

1. A callback registered with [TlsClientHelloBytesCallback][ms_learn_tlsclienthellobytescallback] calls [`TryParse`][code_TryParse] and stores the parsed signature algorithms, represented by [`TlsSignatureScheme`][code_TlsSignatureScheme], in the [ConnectionContext][ms_learn_ConnectionContext].
2. A callback registered with [ServerCertificateSelector][ms_learn_servercertificateselector] reads those signature algorithms from the [ConnectionContext][ms_learn_ConnectionContext].
3. If the client supports ECDSA, the server returns the ECDSA certificate. Otherwise, if the client supports RSA, the server returns the RSA certificate.

## Project Structure

```bash
# Project root
.
├── src/                           # Source code root
│   └── System.Utils/              # Main library project
│       └── code/
│           ├── Buffers/           # Buffer utilities
│           └── Net/
│               └── Security/      # TLS
└── tests/                         # Test code root
    └── System.Utils.Tests/        # Test project
        └── code/
            ├── UnitTests/         # Unit tests for core logic
            └── IntegrationTests/  # Integration tests

```

## Running Tests

To build the project and run the tests on Windows:

- Install WSL with a Linux distribution.
- Install the [.NET 10 SDK][dotnet_10_sdk].
- Use VS Code with:
  - **Remote - WSL** (`ms-vscode-remote.remote-wsl`)
  - **C# Dev Kit** (`ms-dotnettools.csdevkit`)

---

[rfc_5246]: https://www.rfc-editor.org/rfc/rfc5246
[rfc_8446]: https://www.rfc-editor.org/rfc/rfc8446
[rfc_8446_clienthello]: https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
[dotnet_10_sdk]: https://dotnet.microsoft.com/en-us/download/dotnet/10.0
[ms_learn_tlsclienthellobytescallback]: https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.tlsclienthellobytescallback?view=aspnetcore-10.0
[ms_learn_servercertificateselector]: https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.servercertificateselector?view=aspnetcore-10.0
[ms_learn_ConnectionContext]: https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.connections.connectioncontext?view=aspnetcore-10.0

[code_TlsClientHelloParser]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
[code_TlsSignatureScheme]: ./src/System.Utils/code/Net/Security/TlsSignatureScheme.cs
[code_TryParse]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
