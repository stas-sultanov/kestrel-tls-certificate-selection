# TLS Server Certificate Selection

[![CodeQL](https://github.com/stas-sultanov/tls-server-certificate-selection/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/stas-sultanov/tls-server-certificate-selection/actions/workflows/github-code-scanning/codeql)
[![Check](https://github.com/stas-sultanov/tls-server-certificate-selection/actions/workflows/check.yml/badge.svg)](https://github.com/stas-sultanov/tls-server-certificate-selection/actions/workflows/check.yml)

A .NET implementation for parsing a TLS `ClientHello` so a server can choose a certificate that matches the client's advertised capabilities before the TLS handshake completes.

The parser is server-agnostic. It works on raw TLS record bytes and extracts only the fields needed for certificate selection.

This repository also includes integration tests that demonstrate the complete flow with ASP.NET Core Kestrel.

## Overview

This repository includes:

- A low-level TLS `ClientHello` parser for .NET.
- A compact model for the certificate-selection data carried by the client handshake.
- Tests that show how to connect the parser to server certificate selection logic.

The implementation is built around TLS 1.2 and TLS 1.3 as defined by [RFC 5246][rfc_5246] and [RFC 8446][rfc_8446].

## Scope And Non-Goals

This repository is focused on parsing `ClientHello` and demonstrating certificate selection. It does not aim to provide:

- A full TLS implementation.
- A full-featured certificate selection policy framework.
- A server abstraction layer over every .NET web server.

Its main goal is to make the `ClientHello` data needed for certificate selection available in a precise and reusable form.

## How It Works

When a client starts a TLS handshake, it sends a `ClientHello` message describing what it supports. That information can be used by the server to present a compatible certificate instead of guessing or using a single certificate for every client.

For certificate selection, the relevant information is not in one single place. The primary source depends on the TLS version:

| TLS version | Primary source for certificate compatibility | Secondary source |
| --- | --- | --- |
| TLS 1.2 | `signature_algorithms` extension | `cipher_suites` |
| TLS 1.3 | `signature_algorithms_cert` extension | `signature_algorithms` |

The `supported_versions` extension is also important because the server needs to know which TLS versions the client is attempting to negotiate. That affects how the rest of the `ClientHello` should be interpreted and which certificate-selection rules should be applied.

This implemenation exists to make that information available early and accurately so the server can choose the right certificate before the handshake completes.

## Implementation Details

[`TlsClientHelloParser`][code_TlsClientHelloParser] parses a TLS plaintext record that contains a handshake message with a `ClientHello`.

If parsing succeeds, [`TlsClientHelloInfo`][code_TlsClientHelloInfo] exposes the following client-offered values:

- `cipher_suites`: the cipher suites offered by the client.
- `signature_algorithms`: the signature schemes the client supports for handshake signatures.
- `signature_algorithms_cert`: the signature schemes the client supports for certificates, primarily relevant for TLS 1.3.
- `supported_versions`: the TLS protocol versions offered by the client.

The parser validates the structure as it reads and returns a [`TlsClientHelloParseErrorCode`][code_TlsClientHelloParseErrorCode] when the input is empty, truncated, malformed, or not a `ClientHello`.

The output model keeps the parsed values as slices over the original bytes and allows them to be copied into strongly typed .NET enums such as [`TlsSignatureScheme`][code_TlsSignatureScheme] and [`TlsProtocolVersion`][code_TlsProtocolVersion].

The implementation is intentionally designed for the hot path of TLS processing:

- It works directly on raw TLS record bytes.
- It preserves parsed data as slices over the original input.
- It is intentionally built to avoid heap allocation during parsing.
- It extracts only the fields needed for certificate selection.

## Kestrel Integration Flow

The core parser does not depend on any specific server. In this repository, the integration example uses Kestrel and looks like this:

1. Receive raw TLS bytes from the incoming connection before certificate selection is finalized.
2. Call [`TryParse`][code_TryParse] on those bytes.
3. Store the parsed client capabilities in connection-scoped state.
4. Select the server certificate that best matches the client's advertised signature support.

The integration tests in this repository demonstrate this flow with Kestrel by combining:

- [`TlsClientHelloBytesCallback`][ms_learn_tlsclienthellobytescallback] to access raw `ClientHello` bytes.
- [`ServerCertificateSelector`][ms_learn_servercertificateselector] to choose the certificate for the connection.

## Kestrel Example

The integration test server:

- Captures the `ClientHello`.
- Parses the TLS record with [`TlsClientHelloParser`][code_TlsClientHelloParser].
- Reads the client's offered signature schemes.
- Selects a certificate from a small in-memory certificate store.

The current example covers these scenarios:

- TLS 1.2 client offering RSA: the server presents an RSA certificate.
- TLS 1.2 client offering ECDSA without RSA preference: the server presents an ECDSA certificate.
- TLS 1.3 client offering ECDSA without RSA preference: the server presents an ECDSA certificate.

This example is intentionally narrow. Its purpose is to prove the certificate-selection approach, not to provide a production-ready policy engine.

## Running Tests Locally

The integration tests are marked with Linux platform support and are intended to run in a Linux environment.<br>
On Windows, the practical setup is:

- Install WSL with a Linux distribution.
- Install the [.NET 10 SDK][dotnet_10_sdk].
- Open the repository inside WSL, or use an editor setup that targets WSL.
- Restore dependencies and run the tests with `dotnet test`.

## License

This project is licensed under the PolyForm Noncommercial License 1.0.0. Non-commercial use is allowed under that license. Commercial use requires prior written permission from the copyright holder.

See [license.md](./license.md) for the full license text.

[rfc_5246]: https://www.rfc-editor.org/rfc/rfc5246
[rfc_8446]: https://www.rfc-editor.org/rfc/rfc8446
[dotnet_10_sdk]: https://dotnet.microsoft.com/en-us/download/dotnet/10.0
[ms_learn_tlsclienthellobytescallback]: https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.tlsclienthellobytescallback?view=aspnetcore-10.0
[ms_learn_servercertificateselector]: https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.servercertificateselector?view=aspnetcore-10.0
[github_workflow_check]: https://github.com/stas-sultanov/tls-server-certificate-selection/actions/workflows/check.yml

[code_TlsClientHelloParser]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
[code_TlsClientHelloInfo]: ./src/System.Utils/code/Net/Security/TlsClientHelloInfo.cs
[code_TlsClientHelloParseErrorCode]: ./src/System.Utils/code/Net/Security/TlsClientHelloParseErrorCode.cs
[code_TlsProtocolVersion]: ./src/System.Utils/code/Net/Security/TlsProtocolVersion.cs
[code_TlsSignatureScheme]: ./src/System.Utils/code/Net/Security/TlsSignatureScheme.cs
[code_TryParse]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
