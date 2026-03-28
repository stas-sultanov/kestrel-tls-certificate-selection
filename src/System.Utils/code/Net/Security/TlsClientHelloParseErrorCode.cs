// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

/// <summary>
/// Defines error code groups for the <see cref="TlsClientHelloParseErrorCode"/> enum.
/// </summary>
file static class ErrorCodeGroup
{
	public const Int32 Data                = 0x0100;
	public const Int32 Record              = 0x0200;
	public const Int32 Handshake           = 0x0300;
	public const Int32 ClientHello         = 0x0400;
	public const Int32 Extension           = 0x0500;
	public const Int32 SignatureSchemeList = 0x0600;
	public const Int32 SupportedVersions   = 0x0700;
}

/// <summary>
/// Defines error codes for the <see cref="TlsClientHelloParser.TryParse"/> method.
/// </summary>
public enum TlsClientHelloParseErrorCode
{
	/// <summary>
	/// No error occurred.
	/// </summary>
	None = 0x0000,

	/// <summary>
	/// An error occurred while reading the data.
	/// </summary>
	ReadError = 0x0001,

	/// <summary>
	/// The input data is empty.
	/// </summary>
	Data_IsEmpty = ErrorCodeGroup.Data | 0x01,

	/// <summary>
	/// The input data.length is invalid.
	/// </summary>
	Data_Length_IsInvalid = ErrorCodeGroup.Data | 0x02,

	/// <summary>
	/// The TLSPlaintext structure is malformed.
	/// </summary>
	TLSPlaintext_Body_IsMalformed = ErrorCodeGroup.Record | 0x01,

	/// <summary>
	/// The TLSPlaintext.type is invalid.
	/// </summary>
	TLSPlaintext_Field_Type_IsInvalid = ErrorCodeGroup.Record | 0x11,

	/// <summary>
	/// The TLSPlaintext.length is invalid.
	/// </summary>
	TLSPlaintext_Field_Length_IsInvalid = ErrorCodeGroup.Record | 0x21,

	/// <summary>
	/// The Handshake structure is malformed.
	/// </summary>
	Handshake_Body_IsMalformed = ErrorCodeGroup.Handshake | 0x01,

	/// <summary>
	/// The Handshake.msg_type is invalid.
	/// </summary>
	Handshake_Field_MessageType_IsInvalid = ErrorCodeGroup.Handshake | 0x11,

	/// <summary>
	/// The Handshake.length is invalid.
	/// </summary>
	Handshake_Field_Length_IsInvalid = ErrorCodeGroup.Handshake | 0x21,

	/// <summary>
	/// The ClientHello structure is malformed.
	/// </summary>
	ClientHello_Body_IsMalformed = ErrorCodeGroup.ClientHello | 0x01,

	/// <summary>
	/// The ClientHello.legacy_session_id.length is invalid.
	/// </summary>
	ClientHello_Field_LegacySessionId_Length_IsInvalid = ErrorCodeGroup.ClientHello | 0x11,

	/// <summary>
	/// The ClientHello.cipher_suites.length is invalid.
	/// </summary>
	ClientHello_Field_CipherSuites_Length_IsInvalid = ErrorCodeGroup.ClientHello | 0x21,

	/// <summary>
	/// The ClientHello.legacy_compression_methods.length is invalid.
	/// </summary>
	ClientHello_Field_LegacyCompressionMethods_Length_IsInvalid = ErrorCodeGroup.ClientHello | 0x31,

	/// <summary>
	/// The ClientHello.extensions.length is invalid.
	/// </summary>
	ClientHello_Field_Extensions_Length_IsInvalid = ErrorCodeGroup.ClientHello | 0x41,

	/// <summary>
	/// The Extension structure is malformed.
	/// </summary>
	Extension_Body_IsMalformed = ErrorCodeGroup.Extension | 0x01,

	/// <summary>
	/// The SignatureSchemeList structure is malformed.
	/// </summary>
	SignatureSchemeList_Body_IsMalformed = ErrorCodeGroup.SignatureSchemeList | 0x01,

	/// <summary>
	/// The SignatureSchemeList.supported_signature_algorithms.length is invalid.
	/// </summary>
	SignatureSchemeList_Field_SupportedSignatureAlgorithms_Length_IsInvalid = ErrorCodeGroup.SignatureSchemeList | 0x11,

	/// <summary>
	/// The SupportedVersions structure is malformed.
	/// </summary>
	SupportedVersions_Body_IsMalformed = ErrorCodeGroup.SupportedVersions | 0x01,

	/// <summary>
	/// The SupportedVersions.versions.length is invalid.
	/// </summary>
	SupportedVersions_Field_Versions_Length_IsInvalid = ErrorCodeGroup.SupportedVersions | 0x11
}
