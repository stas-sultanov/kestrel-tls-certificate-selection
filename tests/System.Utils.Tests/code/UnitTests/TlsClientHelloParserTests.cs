// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.UnitTests;

using System.Buffers;
using System.Net.Security;

/// <summary>
/// Unit tests for <see cref="TlsClientHelloParser"/> class.
/// </summary>
[TestCategory("UnitTests")]
[TestClass]
public sealed class TlsClientHelloParserTests
{
	#region Test Methods: Fail on Data

	[TestMethod]
	public void TryParse_Fail_Data_IsEmpty()
	{
		// Data is empty to trigger validation failure.
		var data = ReadOnlySequence<Byte>.Empty;
		var expectedErrorCode = TlsClientHelloParseErrorCode.Data_IsEmpty;

		TestTryParseData(data, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_Data_LengthIsInvalid()
	{
		// Data length must be at least 5 bytes to contain a valid TLS record, so use 4 bytes.
		var data = new ReadOnlySequence<Byte>(new Byte[4]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Data_Length_IsInvalid;

		TestTryParseData(data, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on TLSPlaintext

	[TestMethod]
	public void TryParse_Fail_TLSPlaintext_Body_IsMalformed()
	{
		// Handshake header is 4 bytes, so declare length greater than actual payload to trigger length validation failure.
		var record = TlsHelper.BuildTLSPlaintext(0x16, 5, new Byte[4]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.TLSPlaintext_Body_IsMalformed;

		TestTryParseRecord(record, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_TLSPlaintext_Field_Type_IsInvalid()
	{
		// Content type must be 0x16 (handshake), so use 0 to trigger validation failure.
		var record = TlsHelper.BuildTLSPlaintext(0, 0, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.TLSPlaintext_Field_Type_IsInvalid;

		TestTryParseRecord(record, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_TLSPlaintext_Field_Length_IsInvalid()
	{
		// Minimum valid handshake length is 4 bytes for the handshake header, so declare less than that.
		var record = TlsHelper.BuildTLSPlaintext(0x16, 3, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.TLSPlaintext_Field_Length_IsInvalid;

		TestTryParseRecord(record, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on Handshake

	[TestMethod]
	public void TryParse_Fail_Handshake_Body_IsMalformed()
	{
		// Declare length of 50 bytes with empty payload to trigger length validation failure.
		var handshake = TlsHelper.BuildHandshake(0x01, 50, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Handshake_Body_IsMalformed;

		TestTryParseHandshake(handshake, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_Handshake_Field_MessageType_IsInvalid()
	{
		// Build a handshake with msg_type set to 0x02 (server_hello) instead of 0x01 (client_hello).
		var handshake = TlsHelper.BuildHandshake(0x02, 0, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Handshake_Field_MessageType_IsInvalid;

		TestTryParseHandshake(handshake, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_Handshake_Field_Length_IsInvalid()
	{
		// Minimum valid ClientHello length is 41 bytes, so use 40 to trigger validation failure.
		var handshake = TlsHelper.BuildHandshake(0x01, 40, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Handshake_Field_Length_IsInvalid;

		TestTryParseHandshake(handshake, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on ClientHello

	[TestMethod]
	public void TryParse_Fail_ClientHello_Body_IsMalformed_CompressionMethodsLength_IsGreater()
	{
		// Declare compression methods length of 2 with only 1 byte payload to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 2, [0, 0], 2, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_ClientHello_Body_IsMalformed_ExtensionsLength_IsLess()
	{
		// Extensions length is 8 bytes while actual data size is 10 bytes.
		var clientHello = TlsHelper.BuildClientHello(0x0303, 0, [], 2, [0, 0], 1, [0], 8, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_ClientHello_Body_IsMalformed_ExtensionsLength_IsGreater()
	{
		// Declare extensions length of 9 bytes with only 8 bytes payload to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHello(0x0303, 0, [], 2, [0, 0], 1, [0], 9, [0, 1, 2, 3, 4, 5, 6, 7]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_ClientHello_Field_LegacyCompressionMethods_Length_IsInvalid()
	{
		// Compression methods length must be at least 1, so use 0 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 2, [0, 0], 0, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Field_LegacyCompressionMethods_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_ClientHello_Field_CipherSuites_Length_IsInvalid_IsZero()
	{
		// Cipher suites length must be greater than zero, so use 0 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 0, [], 10, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Field_CipherSuites_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_ClientHello_Field_CipherSuites_Length_IsInvalid_IsOdd()
	{
		// Cipher suites length must be even (each suite is 2 bytes), so use 3 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 3, [1, 2, 3], 1, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Field_CipherSuites_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_ClientHello_Field_LegacySessionId_Length_IsInvalid_IsGreaterThan32()
	{
		// Maximum valid session ID length is 32 bytes, so use 33 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 33, [], 2, [0, 0], 1, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Field_LegacySessionId_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_ClientHello_Field_Extensions_Length_IsInvalid_ValueIsLessThan4()
	{
		// Minimum valid extensions length is 4 bytes, so use 3 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHello(0x0303, 0, [], 2, [0, 0], 1, [0], 3, [0, 1, 2]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_Field_Extensions_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on Extension

	[TestMethod]
	public void TryParse_Fail_Extension_Body_IsMalformed_LengthIsGreater()
	{
		// Declare extensions length of 5 bytes with only 4 bytes payload to trigger validation failure.
		var extension = TlsHelper.BuildExtension(1, 5, [0, 1, 2, 3]);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Extension_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_Extension_Field_ExtensionData_Length_IsInvalid()
	{
		// Declare extensions length of 3 bytes with only 4 bytes payload to trigger validation failure.
		var extension = TlsHelper.BuildExtension(1, 3, [0, 1, 2, 3]);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ReadError;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on Signature Algorithms

	[TestMethod]
	public void TryParse_Fail_SignatureSchemeList_Body_IsMalformed()
	{
		// length is 4 bytes, actual data is 2 bytes
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(4, [0x0401]);
		var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_SignatureSchemeList_Field_SupportedSignatureAlgorithms_Length_IsInvalid_ValueIsZero()
	{
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(0, []);
		var extension0 = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var extension1 = TlsHelper.BuildExtension(1, 4, [0, 1, 2, 3]);
		// Include 2nd extension to overcome < 8 bytes length check
		var clientHello = TlsHelper.BuildClientHelloTls13([..extension0, ..extension1]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_Field_SupportedSignatureAlgorithms_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_SignatureSchemeList_Field_SupportedSignatureAlgorithms_Length_IsInvalid_ValueIsOdd()
	{
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(3, [0x0401, 0x0501]);
		var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_Field_SupportedSignatureAlgorithms_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_SignatureAlgorithms_SupportedSignatureAlgorithms_LengthIsLessThanData()
	{
		// length is 2 bytes, actual data is 4 bytes
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(2, [0x0401, 0x0501]);
		var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_SignatureAlgorithms_SupportedSignatureAlgorithms_LengthIsGreaterThanData_WhenFollowedByAnotherExtension()
	{
		// length is 6 bytes, actual data is 2 bytes
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(6, [0x0401]);
		var extension0 = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var extension1 = TlsHelper.BuildExtension(0x0002, 4, [0x00, 0x00, 0x00, 0x00]);
		var clientHello = TlsHelper.BuildClientHelloTls13([..extension0, ..extension1]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on Supported Versions

	[TestMethod]
	public void TryParse_Fail_SupportedVersions_Body_IsMalformed()
	{
		// length is 4 bytes, actual data is 2 bytes
		var supportedVersions = TlsHelper.BuildSupportedVersions(4, [TlsProtocolVersion.Tls13]);
		var extension = TlsHelper.BuildExtension(43, (UInt16) supportedVersions.Length, supportedVersions);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SupportedVersions_Body_IsMalformed;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_SupportedVersions_Field_Versions_Length_IsInvalid_Zero()
	{
		var supportedVersions = TlsHelper.BuildSupportedVersions(0, []);
		var extension0 = TlsHelper.BuildExtension(43, (UInt16) supportedVersions.Length, supportedVersions);
		// Filler extension to overcome < 8 bytes length check for extensions.
		var extension1 = TlsHelper.BuildExtension(0, 8, [0, 1, 2, 3, 4, 5, 6, 7]);
		var clientHello = TlsHelper.BuildClientHelloTls13([..extension1, ..extension0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SupportedVersions_Field_Versions_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_SupportedVersions_Field_Versions_Length_IsInvalid_Odd()
	{
		var extension = TlsHelper.BuildExtension(43, 4, [0x03, 0x02, 0x01, 0x00]);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SupportedVersions_Field_Versions_Length_IsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Succeed

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls12_IsValidWithoutExtensions()
	{
		var expectedCipherSuites = new TlsCipherSuite []
		{
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256
		};
		var cipherSuitesAsBytes = TlsHelper.BuildCipherSuites(expectedCipherSuites);
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], (UInt16) cipherSuitesAsBytes.Length, cipherSuitesAsBytes, 1, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.None;

		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			var cipherSuites = new TlsCipherSuite[info.CipherSuitesCount];
			var copyResult = info.TryCopyCipherSuites(cipherSuites);
			return cipherSuites.SequenceEqual(expectedCipherSuites);
		});
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls12_IsValidWithZeroExtensions()
	{
		var expectedCipherSuites = new TlsCipherSuite []
		{
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256
		};
		var cipherSuitesAsBytes = TlsHelper.BuildCipherSuites(expectedCipherSuites);
		var clientHello = TlsHelper.BuildClientHello(0x0303, 0, [], (UInt16) cipherSuitesAsBytes.Length, cipherSuitesAsBytes, 1, [0], 0, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.None;

		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			var cipherSuites = new TlsCipherSuite[info.CipherSuitesCount];
			var copyResult = info.TryCopyCipherSuites(cipherSuites);
			return cipherSuites.SequenceEqual(expectedCipherSuites);
		});
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls13_IsValidWithSignatureAlgorithms()
	{
		var expectedSignatureAlgorithms = new TlsSignatureScheme[]
		{
			TlsSignatureScheme.rsa_pkcs1_sha256,
			TlsSignatureScheme.ecdsa_secp521r1_sha512
		};
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(4, Array.ConvertAll(expectedSignatureAlgorithms, value => (UInt16) value));
		var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.None;

		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			Span<TlsSignatureScheme> signatureSchemes = stackalloc TlsSignatureScheme[info.SignatureAlgorithmsCount];
			var copyResult = info.TryCopySignatureAlgorithms(signatureSchemes);
			return signatureSchemes.SequenceEqual(expectedSignatureAlgorithms);
		});
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls13_IsValidWithSignatureAlgorithmsCert()
	{
		var expectedSignatureAlgorithmsCert = new TlsSignatureScheme[]
		{
			TlsSignatureScheme.ed25519, TlsSignatureScheme.rsa_pkcs1_sha384
		};
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(4, Array.ConvertAll(expectedSignatureAlgorithmsCert, value => (UInt16) value));
		var extension = TlsHelper.BuildExtension(50, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.None;

		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			Span<TlsSignatureScheme> signatureSchemesCert = stackalloc TlsSignatureScheme[info.SignatureAlgorithmsCertCount];
			var copyResult = info.TryCopySignatureAlgorithmsCert(signatureSchemesCert);
			return signatureSchemesCert.SequenceEqual(expectedSignatureAlgorithmsCert);
		});
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls13_IsValidWithSupportedVersions()
	{
		var expectedSupportedVersions = new TlsProtocolVersion[]
		{
			TlsProtocolVersion.Tls12, TlsProtocolVersion.Tls13
		};
		var supportedVersions = TlsHelper.BuildSupportedVersions((Byte) (expectedSupportedVersions.Length*2), expectedSupportedVersions);
		var extension = TlsHelper.BuildExtension(43, (UInt16) supportedVersions.Length, supportedVersions);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.None;

		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			Span<TlsProtocolVersion> supportedVersions = stackalloc TlsProtocolVersion[info.SupportedVersionsCount];
			var copyResult = info.TryCopySupportedVersions(supportedVersions);
			return supportedVersions.SequenceEqual(expectedSupportedVersions);
		});
	}

	#endregion

	#region Helper Methods

	/// <summary>
	/// A helper method to parse ClientHello bytes.
	/// </summary>
	/// <param name="clientHello">The ClientHello bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseClientHello
	(
		Byte[] clientHello,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		// 0x01 is HandshakeType.client_hello.
		var handshake = TlsHelper.BuildHandshake(0x01, (UInt32) clientHello.Length, clientHello);

		TestTryParseHandshake(handshake, expectedErrorCode, isAsExpected);
	}

	/// <summary>
	/// A helper method to parse Handshake bytes.
	/// </summary>
	/// <param name="handshake">The TLS handshake bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseHandshake
	(
		Byte[] handshake,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		// 0x16 is ContentType.handshake, 0x0303 is legacy_record_version for TLS 1.2 and TLS 1.3.
		var record = TlsHelper.BuildTLSPlaintext(0x16, (UInt16) handshake.Length, handshake);

		TestTryParseRecord(record, expectedErrorCode, isAsExpected);
	}

	/// <summary>
	/// A helper method to parse TLS record bytes.
	/// </summary>
	/// <param name="record">The TLS record bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseRecord
	(
		Byte[] record,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		var data = new ReadOnlySequence<Byte>(record);

		TestTryParseData(data, expectedErrorCode, isAsExpected);
	}

	/// <summary>
	/// A helper method to parse data bytes as a TLS record.
	/// </summary>
	/// <param name="data">The TLS record bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseData
	(
		ReadOnlySequence<Byte> data,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		var result = TlsClientHelloParser.TryParse(data, out var info);

		Assert.AreEqual(expectedErrorCode, result);

		var asExpected = isAsExpected(info);

		Assert.IsTrue(asExpected);
	}

	#endregion
}
