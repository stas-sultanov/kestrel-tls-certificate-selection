// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

/// <summary>
/// TLS protocol version enum as defined in RFC 8446 and RFC 5246.
/// </summary>
/// <remarks>
/// Defined according to <see href="https://www.rfc-editor.org/rfc/rfc8446">RFC 8446</see> and <see href="https://www.rfc-editor.org/rfc/rfc5246">RFC 5246</see>.
/// </remarks>
public enum TlsProtocolVersion : UInt16
{
	/// <summary>
	/// No version.
	/// </summary>
	None = 0x0000,

	/// <summary>
	/// TLS 1.2
	/// </summary>
	Tls12 = 0x0303,

	/// <summary>
	/// TLS 1.3
	/// </summary>
	Tls13 = 0x0304
}
