// Copyright (c) 2026 Apple Inc. Licensed under MIT License.

import Foundation
import Crypto
import _CryptoExtras
import SwiftASN1
import X509

///Generates a throwaway "Apple-like" RSA PKI (root, WWDR intermediate, receipt signing leaf) and CMS-signs synthetic
///legacy app receipts with it, so ``AppReceiptVerifier`` can be exercised without any real Apple key material or a
///checked-in receipt.
public final class ReceiptCreator: Sendable {

    private static let WWDR_INTERMEDIATE_OID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 2, 1]
    private static let RECEIPT_SIGNER_OID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 11, 1]

    ///The common names of the chain, so a test can aim a certificate at the step of chain assembly it wants to reach.
    public static let INTERMEDIATE_NAME = "Test WWDR CA"
    public static let ROOT_NAME = "Test App Store Root CA"

    private static let SIGNED_DATA_OID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 2]
    private static let DATA_OID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 1]
    private static let CONTENT_TYPE_ATTRIBUTE_OID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 3]
    private static let MESSAGE_DIGEST_ATTRIBUTE_OID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 4]
    private static let SIGNING_TIME_ATTRIBUTE_OID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 5]
    public static let SHA1_OID: ASN1ObjectIdentifier = [1, 3, 14, 3, 2, 26]
    public static let SHA256_OID: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    private static let UNKNOWN_ATTRIBUTE_OID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 99999, 1]
    private static let RSA_ENCRYPTION_OID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 1]

    private static let CONTEXT_TAG_0 = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    private static let DAY: TimeInterval = 86400

    ///A well-formed ASN.1 SEQUENCE that is not a certificate, for a container carrying an undecodable one.
    private static let MALFORMED_CERTIFICATE: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]

    ///Signature bytes for a container that is rejected before any signature is checked.
    private static let UNCHECKED_SIGNATURE: [UInt8] = [UInt8](repeating: 0, count: 16)

    ///Leaf first, then intermediate, then root; a self-signed creator holds one entry.
    private let chain: [Certificate]
    private let signingKey: _RSA.Signing.PrivateKey

    private init(chain: [Certificate], signingKey: _RSA.Signing.PrivateKey) {
        self.chain = chain
        self.signingKey = signingKey
    }

    ///A chain carrying both Apple marker OIDs, with a validity window wide enough to cover any plausible receipt
    ///creation date: the chain of a receipt is evaluated at the date the receipt was created, not now.
    ///
    ///- Parameter receiptSignerOid: Whether the leaf carries the receipt-signing marker OID
    ///- Parameter wwdrIntermediateOid: Whether the intermediate carries the WWDR marker OID
    ///- Parameter ocspResponderUri: The OCSP responder the leaf names, which only a verifier with online checks
    ///enabled ever queries
    ///- Parameter notBefore: The start of the validity window of every certificate in the chain
    ///- Parameter notAfter: The end of the validity window of every certificate in the chain
    public static func createReceiptCreator(receiptSignerOid: Bool = true, wwdrIntermediateOid: Bool = true, ocspResponderUri: String? = nil, notBefore: Date = daysAgo(3650), notAfter: Date = inOneYear()) throws -> ReceiptCreator {
        let rootKey = try rsaKey()
        let intermediateKey = try rsaKey()
        let leafKey = try rsaKey()
        let rootName = distinguishedName(ROOT_NAME)
        let intermediateName = distinguishedName(INTERMEDIATE_NAME)
        let root = try certificate(subject: rootName, subjectKey: rootKey, issuer: rootName, issuerKey: rootKey, certificateAuthority: true, markerOid: nil, notBefore: notBefore, notAfter: notAfter)
        let intermediate = try certificate(subject: intermediateName, subjectKey: intermediateKey, issuer: rootName, issuerKey: rootKey, certificateAuthority: true, markerOid: wwdrIntermediateOid ? WWDR_INTERMEDIATE_OID : nil, notBefore: notBefore, notAfter: notAfter)
        let leaf = try certificate(subject: distinguishedName("Test Receipt Signing"), subjectKey: leafKey, issuer: intermediateName, issuerKey: intermediateKey, certificateAuthority: false, markerOid: receiptSignerOid ? RECEIPT_SIGNER_OID : nil, ocspResponderUri: ocspResponderUri, notBefore: notBefore, notAfter: notAfter)
        return ReceiptCreator(chain: [leaf, intermediate, root], signingKey: leafKey)
    }

    ///A single self-signed certificate, as an Xcode-generated receipt carries; such a receipt is never chain verified.
    public static func createSelfSignedReceiptCreator() throws -> ReceiptCreator {
        let key = try rsaKey()
        let name = distinguishedName("Test Xcode Receipt Signing")
        let certificate = try certificate(subject: name, subjectKey: key, issuer: name, issuerKey: key, certificateAuthority: false, markerOid: RECEIPT_SIGNER_OID, notBefore: daysAgo(3650), notAfter: inOneYear())
        return ReceiptCreator(chain: [certificate], signingKey: key)
    }

    ///The root of this chain, in the form the verifier's initializer accepts.
    public var rootCertificate: Data {
        var serializer = DER.Serializer()
        try! serializer.serialize(chain[chain.count - 1])
        return Data(serializer.serializedBytes)
    }

    ///CMS-signs `payload` as encapsulated content, embedding the chain.
    ///
    ///- Parameter embeddedCertificates: How many certificates of the chain, starting at the leaf, to embed in the container
    ///- Parameter signingTime: The CMS signing time attribute, which a stricter verifier would require to fall inside
    ///the signer certificate's validity window, so an old receipt signed by a since expired certificate needs its
    ///original signing time
    ///- Parameter signedAttributes: Whether to sign through a set of signed attributes, as a receipt produced by
    ///BouncyCastle does, rather than over the payload directly, as genuine App Store receipts do
    ///- Parameter segmentedContent: Whether to encapsulate the payload in a constructed, segmented OCTET STRING, the
    ///BER shape genuine App Store receipts arrive in, rather than a single primitive one
    ///- Parameter paddingCertificates: Unrelated certificates embedded on top of the chain, as a receipt bloated to
    ///make chain assembly expensive carries
    ///- Parameter paddingSubject: The name the padding certificates are issued to and by, which decides the step of
    ///chain assembly they become candidates at
    ///- Parameter paddingBeforeChain: Whether the padding certificates are embedded ahead of the chain, so that the
    ///first certificate in the container is not the one the signer info identifies
    ///- Parameter digestAlgorithm: The digest algorithm the container declares, which also selects the digest the
    ///signature is made over, as legacy App Store receipts are SHA-1 signed
    ///- Parameter messageDigest: Whether the signed attributes carry the message digest attribute that binds them to
    ///the payload
    ///- Parameter unknownSignedAttribute: Whether to sign an additional attribute this library does not model, which
    ///sorts after the message digest in the DER SET OF
    ///- Parameter signedByAnotherKey: Whether to sign with a key unrelated to the leaf certificate, leaving the chain
    ///and the message digest intact and only the signature wrong
    ///- Parameter malformedCertificate: Whether to embed a node that does not decode as a certificate
    ///- Parameter digestAlgorithmParameters: Whether the digest algorithm identifiers carry the DER NULL
    ///parameters RFC 5754 lets a SHA-2 producer leave out
    ///- Parameter encapsulatedPayloads: How many copies of the payload the `[0] EXPLICIT` content wrapper holds;
    ///it holds exactly one, and a verifier that took the first of several would accept a receipt carrying one the
    ///signature does not cover
    ///- Parameter omitCertificates: Whether to leave out the optional certificates field, which CMS allows and
    ///which leaves nothing in the container to identify the signer with
    public func signReceipt(_ payload: [UInt8], embeddedCertificates: Int? = nil, signingTime: Date = Date(), signedAttributes: Bool = true, segmentedContent: Bool = false, paddingCertificates: Int = 0, paddingSubject: String = ReceiptCreator.INTERMEDIATE_NAME, paddingBeforeChain: Bool = false, digestAlgorithm: ASN1ObjectIdentifier = ReceiptCreator.SHA256_OID, messageDigest: Bool = true, unknownSignedAttribute: Bool = false, signedByAnotherKey: Bool = false, malformedCertificate: Bool = false, digestAlgorithmParameters: Bool = true, encapsulatedPayloads: Int = 1, omitCertificates: Bool = false) throws -> Data {
        let signedAttributeBytes = signedAttributes ? try ReceiptCreator.signedAttributeSet(payload: payload, signingTime: signingTime, digestAlgorithm: digestAlgorithm, messageDigest: messageDigest, unknownSignedAttribute: unknownSignedAttribute) : nil
        let signature = try ReceiptCreator.sign(signedAttributeBytes ?? payload, with: signedByAnotherKey ? ReceiptCreator.rsaKey() : signingKey, digestAlgorithm: digestAlgorithm)
        let embeddedChain = Array(chain.prefix(embeddedCertificates ?? chain.count))
        let padding = try (0..<paddingCertificates).map { _ in try ReceiptCreator.paddingCertificate(paddingSubject) }
        let embeddedCertificateList = paddingBeforeChain ? padding + embeddedChain : embeddedChain + padding

        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(ReceiptCreator.SIGNED_DATA_OID)
            try coder.appendConstructedNode(identifier: ReceiptCreator.CONTEXT_TAG_0) { coder in
                try coder.appendConstructedNode(identifier: .sequence) { coder in
                    try coder.serialize(1)
                    try coder.serializeSetOf([ReceiptCreator.algorithmIdentifier(digestAlgorithm, parameters: digestAlgorithmParameters)])
                    // encapContentInfo ::= SEQUENCE { eContentType OBJECT IDENTIFIER, eContent [0] EXPLICIT OCTET STRING }
                    try coder.appendConstructedNode(identifier: .sequence) { coder in
                        try coder.serialize(ReceiptCreator.DATA_OID)
                        try coder.appendConstructedNode(identifier: ReceiptCreator.CONTEXT_TAG_0) { coder in
                            for _ in 0..<encapsulatedPayloads {
                                if segmentedContent {
                                    let split = payload.count / 2
                                    try coder.appendConstructedNode(identifier: .octetString) { coder in
                                        try coder.serialize(ASN1OctetString(contentBytes: payload[..<split]))
                                        try coder.serialize(ASN1OctetString(contentBytes: payload[split...]))
                                    }
                                } else {
                                    try coder.serialize(ASN1OctetString(contentBytes: payload[...]))
                                }
                            }
                        }
                    }
                    if !omitCertificates {
                        coder.appendConstructedNode(identifier: ReceiptCreator.CONTEXT_TAG_0) { coder in
                            for certificate in embeddedCertificateList {
                                try! coder.serialize(certificate)
                            }
                            if malformedCertificate {
                                coder.serializeRawBytes(ReceiptCreator.MALFORMED_CERTIFICATE)
                            }
                        }
                    }
                    try coder.serializeSetOf([try signerInfo(signedAttributeBytes: signedAttributeBytes, signature: signature, digestAlgorithm: digestAlgorithm, digestAlgorithmParameters: digestAlgorithmParameters)])
                }
            }
        }
        return Data(serializer.serializedBytes)
    }

    ///The extra OCTET STRING wrapper Xcode-generated receipts put around the payload.
    public static func doubleWrap(_ payload: [UInt8]) -> [UInt8] {
        var serializer = DER.Serializer()
        try! serializer.serialize(ASN1OctetString(contentBytes: payload[...]))
        return serializer.serializedBytes
    }

    public static func attributeSet() -> AttributeSet {
        return AttributeSet()
    }

    ///Builds a receipt attribute SET, the shape both the receipt payload and the value of an in-app purchase attribute
    ///take. Each attribute is `SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }`.
    public final class AttributeSet {
        private var attributes: [DERBytes] = []

        fileprivate init() {}

        ///An attribute whose value is a DER UTF8String, e.g. the bundle identifier.
        @discardableResult
        public func string(_ type: Int64, _ value: String) -> AttributeSet {
            var serializer = DER.Serializer()
            try! serializer.serialize(ASN1UTF8String(value))
            return raw(type, serializer.serializedBytes)
        }

        ///An attribute whose value is a DER IA5String holding an RFC 3339 date.
        @discardableResult
        public func date(_ type: Int64, _ value: String) -> AttributeSet {
            var serializer = DER.Serializer()
            try! serializer.serialize(try! ASN1IA5String(value))
            return raw(type, serializer.serializedBytes)
        }

        ///An attribute whose value is a DER PrintableString, one of the string types Apple uses interchangeably.
        @discardableResult
        public func printableString(_ type: Int64, _ value: String) -> AttributeSet {
            var serializer = DER.Serializer()
            try! serializer.serialize(try! ASN1PrintableString(value))
            return raw(type, serializer.serializedBytes)
        }

        ///An attribute whose value is a DER INTEGER, e.g. a purchase quantity.
        @discardableResult
        public func integer(_ type: Int64, _ value: Int64) -> AttributeSet {
            var serializer = DER.Serializer()
            try! serializer.serialize(value)
            return raw(type, serializer.serializedBytes)
        }

        ///An attribute whose value bytes are used as-is, e.g. an opaque value or a nested SET.
        @discardableResult
        public func raw(_ type: Int64, _ value: [UInt8]) -> AttributeSet {
            var serializer = DER.Serializer()
            try! serializer.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(type)
                try coder.serialize(1)
                try coder.serialize(ASN1OctetString(contentBytes: value[...]))
            }
            attributes.append(DERBytes(serializer.serializedBytes))
            return self
        }

        ///An attribute carrying a fourth element beyond the three this library reads, as a receipt from a later
        ///App Store version would.
        @discardableResult
        public func rawWithExtraElement(_ type: Int64, _ value: [UInt8]) -> AttributeSet {
            var serializer = DER.Serializer()
            try! serializer.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(type)
                try coder.serialize(1)
                try coder.serialize(ASN1OctetString(contentBytes: value[...]))
                try coder.serialize(1)
            }
            attributes.append(DERBytes(serializer.serializedBytes))
            return self
        }

        public func build() -> [UInt8] {
            var serializer = DER.Serializer()
            try! serializer.serializeSetOf(attributes)
            return serializer.serializedBytes
        }
    }

    ///Containers with a piece missing from each structure the verifier indexes into, paired with what each one
    ///leaves out. None of them is signed: every one has to be rejected while the container is being read, and code
    ///that indexed into one of these without first checking its length would trap rather than report a failure.
    public static func truncatedContainers() -> [(String, Data)] {
        return [
            ("content info carrying no content", der { coder in
                try coder.appendConstructedNode(identifier: .sequence) { coder in
                    try coder.serialize(SIGNED_DATA_OID)
                }
            }),
            ("encapsulated content info carrying no payload", signedDataContainer { coder in
                try coder.serialize(1)
                try coder.serializeSetOf([algorithmIdentifier(SHA256_OID)])
                try coder.appendConstructedNode(identifier: .sequence) { coder in
                    try coder.serialize(DATA_OID)
                }
                coder.appendConstructedNode(identifier: .set) { _ in }
            }),
            ("signer identifier carrying no serial number", signedDataContainer { coder in
                try signedDataPrefix(&coder)
                try signerInfos(&coder) { coder in
                    try coder.serialize(1)
                    try coder.appendConstructedNode(identifier: .sequence) { coder in
                        try coder.serialize(distinguishedName(INTERMEDIATE_NAME))
                    }
                    try coder.serialize(algorithmIdentifier(SHA256_OID))
                    try coder.serialize(algorithmIdentifier(RSA_ENCRYPTION_OID))
                    try coder.serialize(ASN1OctetString(contentBytes: UNCHECKED_SIGNATURE[...]))
                }
            }),
            ("digest algorithm identifier carrying no algorithm", signedDataContainer { coder in
                try signedDataPrefix(&coder)
                try signerInfos(&coder) { coder in
                    try coder.serialize(1)
                    try signerIdentifier(&coder)
                    coder.appendConstructedNode(identifier: .sequence) { _ in }
                    try coder.serialize(algorithmIdentifier(RSA_ENCRYPTION_OID))
                    try coder.serialize(ASN1OctetString(contentBytes: UNCHECKED_SIGNATURE[...]))
                }
            }),
            ("signed attribute carrying no value", signedDataContainer { coder in
                try signedDataPrefix(&coder)
                try signerInfos(&coder) { coder in
                    try coder.serialize(1)
                    try signerIdentifier(&coder)
                    try coder.serialize(algorithmIdentifier(SHA256_OID))
                    try coder.appendConstructedNode(identifier: CONTEXT_TAG_0) { coder in
                        // The message digest attribute, the one attribute whose value is read
                        try coder.appendConstructedNode(identifier: .sequence) { coder in
                            try coder.serialize(MESSAGE_DIGEST_ATTRIBUTE_OID)
                        }
                    }
                    try coder.serialize(algorithmIdentifier(RSA_ENCRYPTION_OID))
                    try coder.serialize(ASN1OctetString(contentBytes: UNCHECKED_SIGNATURE[...]))
                }
            }),
            ("signer info carrying no signature", signedDataContainer { coder in
                try signedDataPrefix(&coder)
                try signerInfos(&coder) { coder in
                    try coder.serialize(1)
                    try signerIdentifier(&coder)
                    try coder.serialize(algorithmIdentifier(SHA256_OID))
                    try coder.appendConstructedNode(identifier: CONTEXT_TAG_0) { coder in
                        try coder.appendConstructedNode(identifier: .sequence) { coder in
                            try coder.serialize(CONTENT_TYPE_ATTRIBUTE_OID)
                            try coder.appendConstructedNode(identifier: .set) { coder in
                                try coder.serialize(DATA_OID)
                            }
                        }
                    }
                    try coder.serialize(algorithmIdentifier(RSA_ENCRYPTION_OID))
                }
            })
        ]
    }

    public static func inOneYear() -> Date {
        return Date().addingTimeInterval(365 * DAY)
    }

    public static func daysAgo(_ days: Int) -> Date {
        return Date().addingTimeInterval(-Double(days) * DAY)
    }

    ///`SignerInfo ::= SEQUENCE { version INTEGER, sid IssuerAndSerialNumber, digestAlgorithm AlgorithmIdentifier,`
    ///`signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL, signatureAlgorithm AlgorithmIdentifier, signature OCTET STRING }`
    private func signerInfo(signedAttributeBytes: [UInt8]?, signature: _RSA.Signing.RSASignature, digestAlgorithm: ASN1ObjectIdentifier, digestAlgorithmParameters: Bool) throws -> DERBytes {
        let leaf = chain[0]
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(1)
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(leaf.issuer)
                try coder.serialize(leaf.serialNumber.bytes)
            }
            try coder.serialize(ReceiptCreator.algorithmIdentifier(digestAlgorithm, parameters: digestAlgorithmParameters))
            if var implicitlyTagged = signedAttributeBytes {
                // The same bytes that were signed, with the SET OF tag swapped back for the IMPLICIT [0] tag
                implicitlyTagged[0] = 0xA0
                coder.serializeRawBytes(implicitlyTagged)
            }
            try coder.serialize(ReceiptCreator.algorithmIdentifier(ReceiptCreator.RSA_ENCRYPTION_OID))
            try coder.serialize(ASN1OctetString(contentBytes: ArraySlice(signature.rawRepresentation)))
        }
        return DERBytes(serializer.serializedBytes)
    }

    ///The signed attributes, serialized as the explicit SET OF the signature is computed over.
    private static func signedAttributeSet(payload: [UInt8], signingTime: Date, digestAlgorithm: ASN1ObjectIdentifier, messageDigest: Bool, unknownSignedAttribute: Bool) throws -> [UInt8] {
        var attributes = [
            try attribute(CONTENT_TYPE_ATTRIBUTE_OID) { coder in
                try coder.serialize(DATA_OID)
            },
            try attribute(SIGNING_TIME_ATTRIBUTE_OID) { coder in
                try coder.serialize(utcTime(signingTime))
            }
        ]
        if messageDigest {
            attributes.append(try attribute(MESSAGE_DIGEST_ATTRIBUTE_OID) { coder in
                try coder.serialize(ASN1OctetString(contentBytes: ArraySlice(digest(payload, digestAlgorithm: digestAlgorithm))))
            })
        }
        if unknownSignedAttribute {
            attributes.append(try attribute(UNKNOWN_ATTRIBUTE_OID) { coder in
                try coder.serialize(ASN1OctetString(contentBytes: ArraySlice([UInt8](repeating: 0, count: 64))))
            })
        }
        var serializer = DER.Serializer()
        try serializer.serializeSetOf(attributes)
        return serializer.serializedBytes
    }

    ///`ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER, content [0] EXPLICIT SignedData }`, with the
    ///fields of the `SignedData` written by the caller.
    private static func signedDataContainer(_ signedDataFields: (inout DER.Serializer) throws -> Void) -> Data {
        return der { coder in
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(SIGNED_DATA_OID)
                try coder.appendConstructedNode(identifier: CONTEXT_TAG_0) { coder in
                    try coder.appendConstructedNode(identifier: .sequence) { coder in
                        try signedDataFields(&coder)
                    }
                }
            }
        }
    }

    ///The version, digest algorithms and encapsulated content info a `SignedData` carries before its signer infos.
    private static func signedDataPrefix(_ coder: inout DER.Serializer) throws {
        try coder.serialize(1)
        try coder.serializeSetOf([algorithmIdentifier(SHA256_OID)])
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(DATA_OID)
            try coder.appendConstructedNode(identifier: CONTEXT_TAG_0) { coder in
                try coder.serialize(ASN1OctetString(contentBytes: []))
            }
        }
    }

    ///`signerInfos SET OF SignerInfo` holding the one signer info written by the caller.
    private static func signerInfos(_ coder: inout DER.Serializer, _ signerFields: (inout DER.Serializer) throws -> Void) throws {
        try coder.appendConstructedNode(identifier: .set) { coder in
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try signerFields(&coder)
            }
        }
    }

    ///`sid ::= IssuerAndSerialNumber SEQUENCE { issuer Name, serialNumber INTEGER }`
    private static func signerIdentifier(_ coder: inout DER.Serializer) throws {
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(distinguishedName(INTERMEDIATE_NAME))
            try coder.serialize(1)
        }
    }

    private static func der(_ build: (inout DER.Serializer) throws -> Void) -> Data {
        var serializer = DER.Serializer()
        try! build(&serializer)
        return Data(serializer.serializedBytes)
    }

    private static func digest(_ bytes: [UInt8], digestAlgorithm: ASN1ObjectIdentifier) -> [UInt8] {
        return digestAlgorithm == SHA1_OID ? Array(Insecure.SHA1.hash(data: bytes)) : Array(SHA256.hash(data: bytes))
    }

    private static func sign(_ bytes: [UInt8], with key: _RSA.Signing.PrivateKey, digestAlgorithm: ASN1ObjectIdentifier) throws -> _RSA.Signing.RSASignature {
        return digestAlgorithm == SHA1_OID
            ? try key.signature(for: Insecure.SHA1.hash(data: bytes), padding: .insecurePKCS1v1_5)
            : try key.signature(for: SHA256.hash(data: bytes), padding: .insecurePKCS1v1_5)
    }

    ///`Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF ANY }`
    private static func attribute(_ oid: ASN1ObjectIdentifier, _ value: (inout DER.Serializer) throws -> Void) throws -> DERBytes {
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(oid)
            try coder.appendConstructedNode(identifier: .set) { coder in
                try value(&coder)
            }
        }
        return DERBytes(serializer.serializedBytes)
    }

    private static func algorithmIdentifier(_ oid: ASN1ObjectIdentifier, parameters: Bool = true) -> DERBytes {
        var serializer = DER.Serializer()
        try! serializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(oid)
            if parameters {
                try coder.serialize(ASN1Null())
            }
        }
        return DERBytes(serializer.serializedBytes)
    }

    private static func utcTime(_ date: Date) throws -> UTCTime {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let components = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return try UTCTime(year: components.year!, month: components.month!, day: components.day!, hours: components.hour!, minutes: components.minute!, seconds: components.second!)
    }

    private static func rsaKey() throws -> _RSA.Signing.PrivateKey {
        return try _RSA.Signing.PrivateKey(keySize: .bits2048)
    }

    ///A self-signed certificate carrying `subject` as both its subject and its issuer, so that it is a candidate at
    ///the step of chain assembly that looks for that name rather than being skipped after one comparison.
    private static func paddingCertificate(_ subject: String) throws -> Certificate {
        let key = try rsaKey()
        return try certificate(subject: distinguishedName(subject), subjectKey: key, issuer: distinguishedName(subject), issuerKey: key, certificateAuthority: true, markerOid: nil, notBefore: daysAgo(3650), notAfter: inOneYear())
    }

    private static func distinguishedName(_ commonName: String) -> DistinguishedName {
        return try! DistinguishedName {
            CommonName(commonName)
        }
    }

    private static func certificate(subject: DistinguishedName, subjectKey: _RSA.Signing.PrivateKey, issuer: DistinguishedName, issuerKey: _RSA.Signing.PrivateKey, certificateAuthority: Bool, markerOid: ASN1ObjectIdentifier?, ocspResponderUri: String? = nil, notBefore: Date, notAfter: Date) throws -> Certificate {
        var extensions = [
            try Certificate.Extension(certificateAuthority ? BasicConstraints.isCertificateAuthority(maxPathLength: nil) : BasicConstraints.notCertificateAuthority, critical: true)
        ]
        if let markerOid {
            // The Apple marker extensions are non-critical and carry a DER NULL as their value
            extensions.append(Certificate.Extension(oid: markerOid, critical: false, value: [0x05, 0x00]))
        }
        if let ocspResponderUri {
            extensions.append(try Certificate.Extension(AuthorityInformationAccess([
                AuthorityInformationAccess.AccessDescription(method: .ocspServer, location: .uniformResourceIdentifier(ocspResponderUri))
            ]), critical: false))
        }
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(subjectKey.publicKey),
            notValidBefore: notBefore,
            notValidAfter: notAfter,
            issuer: issuer,
            subject: subject,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions(extensions),
            issuerPrivateKey: Certificate.PrivateKey(issuerKey)
        )
    }
}

///Already-encoded DER, so pieces built separately can be nested and sorted into a SET OF.
struct DERBytes: DERSerializable {
    private let bytes: [UInt8]

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    func serialize(into coder: inout DER.Serializer) throws {
        coder.serializeRawBytes(bytes)
    }
}
