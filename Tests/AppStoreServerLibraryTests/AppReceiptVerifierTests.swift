// Copyright (c) 2026 Apple Inc. Licensed under MIT License.

import XCTest
@testable import AppStoreServerLibrary

import SwiftASN1

final class AppReceiptVerifierTests: XCTestCase {

    private static let BUNDLE_ID = "com.example"
    private static let XCODE_BUNDLE_ID = "com.example.naturelab.backyardbirds.example"
    private static let APP_VERSION = "1.2.3"
    private static let ORIGINAL_APP_VERSION = "1.0"
    private static let OPAQUE_VALUE: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
    private static let SHA1_HASH: [UInt8] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0x11, 0x22, 0x33, 0x44]
    ///The DER encoding of the PKCS#7 signedData content type OID, 1.2.840.113549.1.7.2
    private static let SIGNED_DATA_OID: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]
    ///An OID this library does not implement as a receipt digest algorithm, 2.16.840.1.101.3.4.2.3
    private static let SHA512_OID: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 3]
    private static let UNKNOWN_RECEIPT_ATTRIBUTE_VALUE: [UInt8] = [0x0d, 0x0e, 0x0a, 0x0d]
    private static let UNKNOWN_IN_APP_ATTRIBUTE_VALUE: [UInt8] = [0x0b, 0x0e, 0x0e, 0x0f]

    private static let RECEIPT_CREATION_DATE = "2024-03-01T12:00:00Z"
    private static let RECEIPT_CREATION_DATE_VALUE = Date(timeIntervalSince1970: 1709294400)
    private static let ORIGINAL_PURCHASE_DATE = "2023-11-15T08:30:00Z"
    private static let ORIGINAL_PURCHASE_DATE_VALUE = Date(timeIntervalSince1970: 1700037000)
    private static let EXPIRATION_DATE = "2030-01-01T00:00:00Z"
    private static let EXPIRATION_DATE_VALUE = Date(timeIntervalSince1970: 1893456000)

    private static let CONSUMABLE_PRODUCT_ID = "com.example.coins"
    private static let CONSUMABLE_PURCHASE_DATE = "2024-01-15T12:00:00Z"
    private static let CONSUMABLE_PURCHASE_DATE_VALUE = Date(timeIntervalSince1970: 1705320000)
    private static let CONSUMABLE_ORIGINAL_PURCHASE_DATE = "2024-01-10T09:00:00Z"
    private static let CONSUMABLE_ORIGINAL_PURCHASE_DATE_VALUE = Date(timeIntervalSince1970: 1704877200)

    private static let SUBSCRIPTION_PRODUCT_ID = "com.example.subscription"
    private static let SUBSCRIPTION_PURCHASE_DATE = "2024-02-01T09:30:00Z"
    private static let SUBSCRIPTION_PURCHASE_DATE_VALUE = Date(timeIntervalSince1970: 1706779800)
    private static let SUBSCRIPTION_EXPIRES_DATE = "2030-02-01T09:30:00Z"
    private static let SUBSCRIPTION_EXPIRES_DATE_VALUE = Date(timeIntervalSince1970: 1896168600)
    private static let SUBSCRIPTION_CANCELLATION_DATE = "2024-06-01T00:00:00Z"
    private static let SUBSCRIPTION_CANCELLATION_DATE_VALUE = Date(timeIntervalSince1970: 1717200000)

    ///A responder URI this library's OCSP requester cannot make a request to, so a query fails as a network error
    ///immediately rather than waiting on a connection that will never be made.
    private static let UNUSABLE_OCSP_RESPONDER = "ocsp://responder.invalid"

    private static let receiptCreator = try! ReceiptCreator.createReceiptCreator()
    private static let sandboxReceipt = try! receiptCreator.signReceipt(receiptPayload("ProductionSandbox", BUNDLE_ID, RECEIPT_CREATION_DATE))
    private static let xcodeReceiptCreator = try! ReceiptCreator.createSelfSignedReceiptCreator()

    public func testAppReceiptDecoding() async throws {
        let receipt = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(AppReceiptVerifierTests.sandboxReceipt)))

        XCTAssertEqual("ProductionSandbox", receipt.receiptType)
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, receipt.bundleId)
        XCTAssertEqual(derEncodedUTF8String(AppReceiptVerifierTests.BUNDLE_ID), receipt.bundleIdBytes)
        XCTAssertEqual(AppReceiptVerifierTests.APP_VERSION, receipt.applicationVersion)
        XCTAssertEqual(AppReceiptVerifierTests.ORIGINAL_APP_VERSION, receipt.originalApplicationVersion)
        XCTAssertEqual(Data(AppReceiptVerifierTests.OPAQUE_VALUE), receipt.opaqueValue)
        XCTAssertEqual(Data(AppReceiptVerifierTests.SHA1_HASH), receipt.sha1Hash)
        XCTAssertEqual(AppReceiptVerifierTests.RECEIPT_CREATION_DATE_VALUE, receipt.receiptCreationDate)
        XCTAssertEqual(AppReceiptVerifierTests.ORIGINAL_PURCHASE_DATE_VALUE, receipt.originalPurchaseDate)
        XCTAssertEqual(AppReceiptVerifierTests.EXPIRATION_DATE_VALUE, receipt.expirationDate)
        XCTAssertEqual(2, receipt.inAppPurchases.count)

        let consumable = receipt.inAppPurchases[0]
        XCTAssertEqual(1, consumable.quantity)
        XCTAssertEqual(AppReceiptVerifierTests.CONSUMABLE_PRODUCT_ID, consumable.productId)
        XCTAssertEqual("70000000000001", consumable.transactionId)
        XCTAssertEqual("70000000000001", consumable.originalTransactionId)
        XCTAssertEqual(AppReceiptVerifierTests.CONSUMABLE_PURCHASE_DATE_VALUE, consumable.purchaseDate)
        XCTAssertEqual(AppReceiptVerifierTests.CONSUMABLE_ORIGINAL_PURCHASE_DATE_VALUE, consumable.originalPurchaseDate)
        XCTAssertEqual(42, consumable.webOrderLineItemId)

        let subscription = receipt.inAppPurchases[1]
        XCTAssertEqual(1, subscription.quantity)
        XCTAssertEqual(AppReceiptVerifierTests.SUBSCRIPTION_PRODUCT_ID, subscription.productId)
        XCTAssertEqual("70000000000002", subscription.transactionId)
        XCTAssertEqual("70000000000002", subscription.originalTransactionId)
        XCTAssertEqual(AppReceiptVerifierTests.SUBSCRIPTION_PURCHASE_DATE_VALUE, subscription.purchaseDate)
        XCTAssertEqual(AppReceiptVerifierTests.SUBSCRIPTION_PURCHASE_DATE_VALUE, subscription.originalPurchaseDate)
        XCTAssertEqual(AppReceiptVerifierTests.SUBSCRIPTION_EXPIRES_DATE_VALUE, subscription.expiresDate)
        XCTAssertEqual(AppReceiptVerifierTests.SUBSCRIPTION_CANCELLATION_DATE_VALUE, subscription.cancellationDate)
        XCTAssertEqual(12345, subscription.webOrderLineItemId)
    }

    ///An in-app purchase attribute that is present but empty means "absent", and the intro offer flag is an integer
    ///that must surface as a boolean, so a caller can distinguish "no expiration" from "expired at epoch".
    public func testInAppPurchaseFlagAndEmptyDateDecoding() async throws {
        let receipt = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(AppReceiptVerifierTests.sandboxReceipt)))

        let consumable = receipt.inAppPurchases[0]
        XCTAssertEqual(false, consumable.isInIntroOfferPeriod)
        XCTAssertNil(consumable.expiresDate)
        XCTAssertNil(consumable.cancellationDate)

        XCTAssertEqual(true, receipt.inAppPurchases[1].isInIntroOfferPeriod)
    }

    ///Attribute types this library does not model must survive decoding with their raw bytes, so a receipt field
    ///Apple adds later stays reachable.
    public func testUnknownAttributesArePreserved() async throws {
        let receipt = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(AppReceiptVerifierTests.sandboxReceipt)))

        XCTAssertEqual(1, receipt.unknownAttributes[9999]?.count)
        XCTAssertEqual(Data(AppReceiptVerifierTests.UNKNOWN_RECEIPT_ATTRIBUTE_VALUE), receipt.unknownAttributes[9999]?[0])
        XCTAssertEqual(Data(AppReceiptVerifierTests.UNKNOWN_IN_APP_ATTRIBUTE_VALUE), receipt.inAppPurchases[0].unknownAttributes[1799]?[0])
    }

    public func testWrongBundleId() async throws {
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox, bundleId: "com.example.other")
        await assertInvalid(.INVALID_APP_IDENTIFIER, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(AppReceiptVerifierTests.sandboxReceipt)))
    }

    public func testWrongEnvironment() async throws {
        let productionReceipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("Production", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.INVALID_ENVIRONMENT, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(productionReceipt)))
    }

    ///A receipt type this library does not recognize maps to no environment at all rather than defaulting to the
    ///verifier's, so an unexpected value can never be mistaken for a match.
    public func testUnknownReceiptType() async throws {
        let unknownTypeReceipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionInternal", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.INVALID_ENVIRONMENT, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(unknownTypeReceipt)))

        let productionVerifier = AppReceiptVerifierTests.verifier(environment: .production)
        await assertInvalid(.INVALID_ENVIRONMENT, await productionVerifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(unknownTypeReceipt)))
    }

    ///Every receipt type the App Store issues maps to the environment that produced it, a Volume Purchase Program
    ///receipt included.
    public func testReceiptTypeEnvironmentMapping() async throws {
        let types: [(String, AppStoreEnvironment)] = [
            ("Production", .production), ("ProductionVPP", .production),
            ("ProductionSandbox", .sandbox), ("ProductionVPPSandbox", .sandbox)]
        for (receiptType, environment) in types {
            let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload(receiptType, AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))
            let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: environment).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
            XCTAssertEqual(receiptType, decoded.receiptType)
        }
    }

    public func testTamperedPayload() async throws {
        var tamperedReceipt = AppReceiptVerifierTests.sandboxReceipt
        // Flip a bit inside the app version of the encapsulated payload; the chain is untouched, so only the
        // signature check can catch this.
        tamperedReceipt[try indexOf(tamperedReceipt, Array(AppReceiptVerifierTests.APP_VERSION.utf8))] ^= 0x01
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(tamperedReceipt)))
    }

    public func testReceiptSignedByForeignRoot() async throws {
        let foreignCreator = try ReceiptCreator.createReceiptCreator()
        let forgedReceipt = try foreignCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(forgedReceipt)))
    }

    public func testLeafWithoutReceiptSigningOid() async throws {
        let creator = try ReceiptCreator.createReceiptCreator(receiptSignerOid: false)
        let receipt = try creator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))
        let verifier = AppReceiptVerifierTests.verifier(creator, environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    public func testIntermediateWithoutWwdrOid() async throws {
        let creator = try ReceiptCreator.createReceiptCreator(wwdrIntermediateOid: false)
        let receipt = try creator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))
        let verifier = AppReceiptVerifierTests.verifier(creator, environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    public func testReceiptWithoutRootCertificateEmbedded() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), embeddedCertificates: 2)
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    public func testReceiptThatIsNotBase64() async throws {
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: "!!!not-base64!!!"))
    }

    public func testReceiptThatIsNotAPkcs7Container() async throws {
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(Data([1, 2, 3, 4]))))
    }

    ///Bytes appended after the container must not be ignored, a verifier that parsed a prefix would accept a receipt
    ///carrying unverified extra data.
    public func testTrailingBytesAfterContainer() async throws {
        let paddedReceipt = AppReceiptVerifierTests.sandboxReceipt + Data([0, 0, 0, 0])
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(paddedReceipt)))
    }

    ///Receipts outlive the certificates that signed them, so with online checks off the chain is evaluated at the
    ///receipt's creation date.
    public func testReceiptSignedByNowExpiredCertificates() async throws {
        let expiredCreator = try ReceiptCreator.createReceiptCreator(notBefore: ReceiptCreator.daysAgo(730), notAfter: ReceiptCreator.daysAgo(365))
        let createdAt = ReceiptCreator.daysAgo(547)
        let receipt = try expiredCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, rfc3339(createdAt)), signingTime: createdAt)

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(expiredCreator, environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(rfc3339(createdAt), rfc3339(decoded.receiptCreationDate!))
    }

    ///Enabling online checks moves the evaluation to now, which is the point of the option: the same receipt must
    ///then fail on the expired chain.
    public func testReceiptSignedByNowExpiredCertificatesWithOnlineChecks() async throws {
        let expiredCreator = try ReceiptCreator.createReceiptCreator(notBefore: ReceiptCreator.daysAgo(730), notAfter: ReceiptCreator.daysAgo(365))
        let createdAt = ReceiptCreator.daysAgo(547)
        let receipt = try expiredCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, rfc3339(createdAt)), signingTime: createdAt)

        let verifier = AppReceiptVerifierTests.verifier(expiredCreator, environment: .sandbox, enableOnlineChecks: true)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///Genuine App Store receipts carry no signed attributes and sign the encapsulated payload directly, unlike the
    ///receipts most CMS tooling produces.
    public func testReceiptWithoutSignedAttributes() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), signedAttributes: false)

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    ///Genuine App Store receipts encapsulate the payload in a constructed OCTET STRING, whose segments have to be
    ///joined before the payload is either digested or decoded.
    public func testReceiptWithSegmentedContent() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), segmentedContent: true)

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
        XCTAssertEqual(2, decoded.inAppPurchases.count)
    }

    ///Xcode-generated receipts are not signed by the App Store, so they are decoded without any chain or signature check.
    public func testXcodeReceiptDecoding() async throws {
        let receipt = try AppReceiptVerifierTests.xcodeReceiptCreator.signReceipt(ReceiptCreator.doubleWrap(AppReceiptVerifierTests.receiptPayload("Xcode", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)))

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(AppReceiptVerifierTests.xcodeReceiptCreator, environment: .xcode).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual("Xcode", decoded.receiptType)
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
        XCTAssertEqual(AppReceiptVerifierTests.APP_VERSION, decoded.applicationVersion)
        XCTAssertEqual(AppReceiptVerifierTests.RECEIPT_CREATION_DATE_VALUE, decoded.receiptCreationDate)
        XCTAssertEqual(2, decoded.inAppPurchases.count)
    }

    ///Skipping the signature checks must not skip the app identity check.
    public func testXcodeReceiptWithWrongBundleId() async throws {
        let receipt = try AppReceiptVerifierTests.xcodeReceiptCreator.signReceipt(ReceiptCreator.doubleWrap(AppReceiptVerifierTests.receiptPayload("Xcode", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)))

        let verifier = AppReceiptVerifierTests.verifier(AppReceiptVerifierTests.xcodeReceiptCreator, environment: .xcode, bundleId: "com.example.other")
        await assertInvalid(.INVALID_APP_IDENTIFIER, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///Skipping the signature checks must not skip the environment check either.
    public func testXcodeReceiptWithWrongEnvironment() async throws {
        let receipt = try AppReceiptVerifierTests.xcodeReceiptCreator.signReceipt(ReceiptCreator.doubleWrap(AppReceiptVerifierTests.receiptPayload("Production", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)))

        let verifier = AppReceiptVerifierTests.verifier(AppReceiptVerifierTests.xcodeReceiptCreator, environment: .xcode)
        await assertInvalid(.INVALID_ENVIRONMENT, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///The embedded certificates are attacker-supplied and are ordered into a chain before anything about the receipt
    ///has been verified, so a receipt carrying more of them than a chain can hold is rejected rather than assembled.
    public func testReceiptWithTooManyEmbeddedCertificates() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), paddingCertificates: 30)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///The limit is on how many certificates are embedded, not on how many a chain needs, so a receipt carrying as
    ///many as the limit allows still verifies and the one beyond it does not.
    public func testReceiptWithTheMaximumEmbeddedCertificates() async throws {
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)

        let atTheLimit = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), paddingCertificates: 7)
        let decoded = try await validReceipt(verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(atTheLimit)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)

        let overTheLimit = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), paddingCertificates: 8)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(overTheLimit)))
    }

    ///A chain is exactly leaf, intermediate and root, so a receipt whose embedded certificates go on chaining past
    ///the root is rejected rather than verified on the first three of them.
    public func testChainAssemblingPastTheExpectedLength() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), paddingCertificates: 1, paddingSubject: ReceiptCreator.ROOT_NAME)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///The chain is assembled from the certificate the signer info identifies, not from whichever certificate the
    ///container happens to carry first.
    public func testSignerCertificateIsTheOneTheSignerInfoIdentifies() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), paddingCertificates: 1, paddingSubject: "Test Unrelated CA", paddingBeforeChain: true)

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    ///The chain, the payload and the message digest can all be intact while the signature is not: a receipt signed
    ///by a key that is not the leaf certificate's is caught by the signature check alone.
    public func testReceiptSignedByAnotherKey() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), signedByAnotherKey: true)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///Signed attributes bind the payload to the signature only through the message digest attribute, so attributes
    ///carrying no digest at all leave the payload unsigned and must be rejected.
    public func testReceiptWithSignedAttributesButNoMessageDigest() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), messageDigest: false)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///A signed attribute this library does not model must not be mistaken for the message digest attribute it does.
    public func testReceiptWithUnknownSignedAttribute() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), unknownSignedAttribute: true)

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    ///Legacy App Store receipts are SHA-1 signed, so the SHA-1 digest algorithm has to select both the digest the
    ///message digest attribute is compared against and the RSA signature algorithm.
    public func testSha1SignedReceipt() async throws {
        let payload = AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)

        let withSignedAttributes = try AppReceiptVerifierTests.receiptCreator.signReceipt(payload, digestAlgorithm: ReceiptCreator.SHA1_OID)
        let decodedWithSignedAttributes = try await validReceipt(verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(withSignedAttributes)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decodedWithSignedAttributes.bundleId)

        // The shape a genuine App Store receipt arrives in: SHA-1 over the payload, with no signed attributes
        let overThePayload = try AppReceiptVerifierTests.receiptCreator.signReceipt(payload, signedAttributes: false, digestAlgorithm: ReceiptCreator.SHA1_OID)
        let decodedOverThePayload = try await validReceipt(verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(overThePayload)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decodedOverThePayload.bundleId)
    }

    ///A digest algorithm this library does not implement must fail verification rather than fall back to one it does.
    public func testReceiptWithUnsupportedDigestAlgorithm() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), digestAlgorithm: AppReceiptVerifierTests.SHA512_OID)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///Nothing identifies the signer when the certificate its signer info names is not in the container, which is a
    ///certificate problem rather than a generic verification failure.
    public func testReceiptWithoutTheSignerCertificate() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), embeddedCertificates: 0)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.INVALID_CERTIFICATE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///The embedded certificates are attacker-supplied, so one that does not decode fails the receipt rather than
    ///being skipped over on the way to a chain assembled from the rest.
    public func testReceiptWithMalformedCertificate() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), malformedCertificate: true)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.INVALID_CERTIFICATE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///Every structure the container walk indexes into is attacker-controlled, so one with an element missing has to
    ///fail verification. Reading past the end of any of them would trap instead, taking the process with it.
    public func testTruncatedContainersAreRejected() async throws {
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)

        for (missingElement, container) in ReceiptCreator.truncatedContainers() {
            switch await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(container)) {
            case .valid(_):
                XCTFail("Expected a \(missingElement) to be rejected")
            case .invalid(let error):
                XCTAssertEqual(VerificationError.VERIFICATION_FAILURE, error, "a \(missingElement)")
            }
        }
    }

    ///The outer container must be a PKCS#7 signedData; another content type is not a receipt even when the bytes
    ///inside it parse as one.
    public func testReceiptThatIsNotSignedDataContentType() async throws {
        var receipt = AppReceiptVerifierTests.sandboxReceipt
        // Retag the content type as 1.2.840.113549.1.7.1 (data); it sits outside everything the signature covers
        receipt[try indexOf(receipt, AppReceiptVerifierTests.SIGNED_DATA_OID) + AppReceiptVerifierTests.SIGNED_DATA_OID.count - 1] = 0x01

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///The payload is a SET of attributes; a payload of any other shape is not a receipt and must not be walked as
    ///though it were.
    public func testPayloadThatIsNotAnAttributeSet() async throws {
        var payload = AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
        // Retag the attribute SET as a SEQUENCE, leaving its contents untouched
        payload[0] = 0x30
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(payload)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///Base64 receipts pick up line breaks in transit, which the decoder ignores rather than rejecting the receipt.
    public func testReceiptWithLineBreaksInBase64() async throws {
        let encoded = AppReceiptVerifierTests.sandboxReceipt.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encoded))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    ///A receipt with no creation date has no signing time to anchor the chain to, so the chain is evaluated at the
    ///current time instead of the receipt failing.
    public func testReceiptWithoutCreationDate() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .string(2, AppReceiptVerifierTests.BUNDLE_ID)
            .build())

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertNil(decoded.receiptCreationDate)
    }

    ///Apple is not consistent about which ASN.1 string type a receipt attribute uses, so a PrintableString decodes
    ///like the UTF8Strings and IA5Strings the other attributes arrive as.
    public func testPrintableStringAttribute() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .printableString(0, "ProductionSandbox")
            .printableString(2, AppReceiptVerifierTests.BUNDLE_ID)
            .date(12, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
            .build())

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual("ProductionSandbox", decoded.receiptType)
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    ///An attribute carrying more than the three elements this library reads is decoded from the three it knows, so
    ///a field Apple adds inside an attribute does not fail the whole receipt.
    public func testAttributeWithAnAdditionalElement() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .rawWithExtraElement(2, Array(derEncodedUTF8String(AppReceiptVerifierTests.BUNDLE_ID)))
            .date(12, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
            .build())

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    ///An attribute value that is not a string at all, or is a string type carrying bytes that are not UTF-8, is a
    ///malformed receipt rather than a field that silently decodes to something else.
    public func testAttributeValueThatIsNotAString() async throws {
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)

        let integerBundleId = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .integer(2, 5)
            .date(12, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
            .build())
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(integerBundleId)))

        // A UTF8String whose contents are not valid UTF-8
        let invalidUtf8BundleId = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .raw(2, [0x0c, 0x02, 0xff, 0xfe])
            .date(12, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
            .build())
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(invalidUtf8BundleId)))
    }

    ///Receipt integers are non-negative, so a negative one is a malformed receipt rather than a value to carry
    ///through to the caller.
    public func testNegativeInAppPurchaseInteger() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .string(2, AppReceiptVerifierTests.BUNDLE_ID)
            .date(12, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
            .raw(17, ReceiptCreator.attributeSet().integer(1701, -1).build())
            .build())

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///A date attribute that is neither empty nor an RFC 3339 date fails the receipt, rather than decoding as the
    ///absent date an empty one means.
    public func testUnparseableReceiptDate() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .string(2, AppReceiptVerifierTests.BUNDLE_ID)
            .date(12, "March 1st, 2024")
            .build())

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///Receipt dates carry fractional seconds as well as whole ones.
    public func testDateWithFractionalSeconds() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .string(2, AppReceiptVerifierTests.BUNDLE_ID)
            .date(12, "2024-03-01T12:00:00.500Z")
            .build())

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(Date(timeIntervalSince1970: 1709294400.5), decoded.receiptCreationDate)
    }

    ///Which id an in-app purchase yields is deterministic: its transaction id, and only when it carries none, its
    ///original transaction id.
    public func testTransactionIdPreferredOverOriginalTransactionId() async throws {
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)

        let bothIds = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptWithPurchase(ReceiptCreator.attributeSet()
            .string(1703, "70000000000003")
            .string(1705, "70000000000004")
            .build()))
        switch await verifier.verifyAndExtractTransactionId(encodedReceipt: encode(bothIds)) {
        case .valid(let transactionId):
            XCTAssertEqual("70000000000003", transactionId)
        case .invalid(let error):
            XCTFail("Expected a valid receipt, got \(error)")
        }

        let originalIdOnly = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptWithPurchase(ReceiptCreator.attributeSet()
            .string(1705, "70000000000004")
            .build()))
        switch await verifier.verifyAndExtractTransactionId(encodedReceipt: encode(originalIdOnly)) {
        case .valid(let transactionId):
            XCTAssertEqual("70000000000004", transactionId)
        case .invalid(let error):
            XCTFail("Expected a valid receipt, got \(error)")
        }
    }

    ///A receipt Xcode actually produced, which unlike the synthetic ones above is BER with indefinite lengths,
    ///segmented octet strings and a double-wrapped payload.
    public func testXcodeGeneratedAppReceiptDecoding() async throws {
        let verifier = try AppReceiptVerifier(rootCertificates: [TestingUtility.readBytes("resources/certs/testCA.der")], bundleId: AppReceiptVerifierTests.XCODE_BUNDLE_ID, environment: .xcode, enableOnlineChecks: false)

        let receipt = try await validReceipt(await verifier.verifyAndDecodeAppReceipt(encodedReceipt: TestingUtility.readFile("resources/xcode/xcode-app-receipt-with-transaction")))

        XCTAssertEqual("Xcode", receipt.receiptType)
        XCTAssertEqual(AppReceiptVerifierTests.XCODE_BUNDLE_ID, receipt.bundleId)
        XCTAssertEqual("1", receipt.applicationVersion)
        XCTAssertEqual(Date(timeIntervalSince1970: 1697679940), receipt.receiptCreationDate)
        XCTAssertEqual(1, receipt.inAppPurchases.count)
        XCTAssertEqual("pass.premium", receipt.inAppPurchases[0].productId)
        XCTAssertEqual("0", receipt.inAppPurchases[0].transactionId)
    }

    ///The output contract this shares with ReceiptUtility, checked against the same receipts.
    public func testXcodeGeneratedAppReceiptTransactionIdExtraction() async throws {
        let verifier = try AppReceiptVerifier(rootCertificates: [TestingUtility.readBytes("resources/certs/testCA.der")], bundleId: AppReceiptVerifierTests.XCODE_BUNDLE_ID, environment: .xcode, enableOnlineChecks: false)

        switch await verifier.verifyAndExtractTransactionId(encodedReceipt: TestingUtility.readFile("resources/xcode/xcode-app-receipt-with-transaction")) {
        case .valid(let transactionId):
            XCTAssertEqual("0", transactionId)
        case .invalid(let error):
            XCTFail("Expected a valid receipt, got \(error)")
        }
        switch await verifier.verifyAndExtractTransactionId(encodedReceipt: TestingUtility.readFile("resources/xcode/xcode-app-receipt-empty")) {
        case .valid(let transactionId):
            XCTAssertNil(transactionId)
        case .invalid(let error):
            XCTFail("Expected a valid receipt, got \(error)")
        }
    }

    ///As with an Xcode receipt, LocalTesting data is not signed by the App Store.
    public func testLocalTestingReceiptDecoding() async throws {
        let receipt = try AppReceiptVerifierTests.xcodeReceiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("LocalTesting", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(AppReceiptVerifierTests.xcodeReceiptCreator, environment: .localTesting).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual("LocalTesting", decoded.receiptType)
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    ///Skipping the signature checks must not skip the app identity check.
    public func testLocalTestingReceiptWithWrongBundleId() async throws {
        let receipt = try AppReceiptVerifierTests.xcodeReceiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("LocalTesting", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))

        let verifier = AppReceiptVerifierTests.verifier(AppReceiptVerifierTests.xcodeReceiptCreator, environment: .localTesting, bundleId: "com.example.other")
        await assertInvalid(.INVALID_APP_IDENTIFIER, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    public func testVerifyAndExtractTransactionId() async throws {
        let result = await AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndExtractTransactionId(encodedReceipt: encode(AppReceiptVerifierTests.sandboxReceipt))
        switch result {
        case .valid(let transactionId):
            XCTAssertEqual("70000000000001", transactionId)
        case .invalid(_):
            XCTAssert(false)
        }
    }

    ///Same output contract as ReceiptUtility: a verified receipt with no in-app purchases yields nil.
    public func testVerifyAndExtractTransactionIdWithoutInAppPurchases() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .string(2, AppReceiptVerifierTests.BUNDLE_ID)
            .date(12, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
            .build())
        let result = await AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndExtractTransactionId(encodedReceipt: encode(receipt))
        switch result {
        case .valid(let transactionId):
            XCTAssertNil(transactionId)
        case .invalid(_):
            XCTAssert(false)
        }
    }

    ///Unlike ReceiptUtility, extraction refuses a receipt that does not verify.
    public func testVerifyAndExtractTransactionIdRejectsForeignReceipt() async throws {
        let foreignCreator = try ReceiptCreator.createReceiptCreator()
        let receipt = try foreignCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))

        let result = await AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndExtractTransactionId(encodedReceipt: encode(receipt))
        switch result {
        case .valid(_):
            XCTAssert(false)
        case .invalid(let error):
            XCTAssertEqual(VerificationError.VERIFICATION_FAILURE, error)
        }
    }

    ///Revocation checking is the other half of what enabling online checks buys, and it is only reachable through
    ///the chain verifier: a receipt whose leaf names an OCSP responder must be queried when they are on, so a
    ///responder that cannot be reached fails it as retryable, and must not be queried at all when they are off.
    public func testOnlineChecksQueryTheOcspResponder() async throws {
        let creator = try ReceiptCreator.createReceiptCreator(ocspResponderUri: AppReceiptVerifierTests.UNUSABLE_OCSP_RESPONDER)
        let receipt = try creator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE))

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(creator, environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)

        let onlineVerifier = AppReceiptVerifierTests.verifier(creator, environment: .sandbox, enableOnlineChecks: true)
        await assertInvalid(.RETRYABLE_VERIFICATION_FAILURE, await onlineVerifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///The certificates are optional in CMS, so a container without them is well formed; it just carries nothing to
    ///identify the signer with, which is a certificate problem rather than a malformed container.
    public func testContainerWithoutACertificatesField() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), omitCertificates: true)

        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)
        await assertInvalid(.INVALID_CERTIFICATE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
    }

    ///An EXPLICIT tag wraps exactly one node: an empty wrapper carries no payload at all, and one carrying a second
    ///payload must be rejected rather than verified on the first, which would leave the second unsigned.
    public func testContentWrapperHoldingOtherThanOnePayload() async throws {
        let payload = AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE)
        let verifier = AppReceiptVerifierTests.verifier(environment: .sandbox)

        let empty = try AppReceiptVerifierTests.receiptCreator.signReceipt(payload, encapsulatedPayloads: 0)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(empty)))

        let twoPayloads = try AppReceiptVerifierTests.receiptCreator.signReceipt(payload, encapsulatedPayloads: 2)
        await assertInvalid(.VERIFICATION_FAILURE, await verifier.verifyAndDecodeAppReceipt(encodedReceipt: encode(twoPayloads)))
    }

    ///RFC 5754 lets a SHA-2 producer leave the parameters out of an algorithm identifier, so an identifier carrying
    ///only its OID names the digest algorithm just as one carrying a DER NULL does.
    public func testDigestAlgorithmWithoutParameters() async throws {
        let receipt = try AppReceiptVerifierTests.receiptCreator.signReceipt(AppReceiptVerifierTests.receiptPayload("ProductionSandbox", AppReceiptVerifierTests.BUNDLE_ID, AppReceiptVerifierTests.RECEIPT_CREATION_DATE), digestAlgorithmParameters: false)

        let decoded = try await validReceipt(AppReceiptVerifierTests.verifier(environment: .sandbox).verifyAndDecodeAppReceipt(encodedReceipt: encode(receipt)))
        XCTAssertEqual(AppReceiptVerifierTests.BUNDLE_ID, decoded.bundleId)
    }

    private static func verifier(_ creator: ReceiptCreator = receiptCreator, environment: AppStoreEnvironment, bundleId: String = BUNDLE_ID, enableOnlineChecks: Bool = false) -> AppReceiptVerifier {
        return try! AppReceiptVerifier(rootCertificates: [creator.rootCertificate], bundleId: bundleId, environment: environment, enableOnlineChecks: enableOnlineChecks)
    }

    private static func receiptPayload(_ receiptType: String, _ bundleId: String, _ creationDate: String) -> [UInt8] {
        return ReceiptCreator.attributeSet()
            .string(0, receiptType)
            .string(2, bundleId)
            .string(3, APP_VERSION)
            .raw(4, OPAQUE_VALUE)
            .raw(5, SHA1_HASH)
            .date(12, creationDate)
            .date(18, ORIGINAL_PURCHASE_DATE)
            .string(19, ORIGINAL_APP_VERSION)
            .date(21, EXPIRATION_DATE)
            .raw(9999, UNKNOWN_RECEIPT_ATTRIBUTE_VALUE)
            .raw(17, consumablePurchase())
            .raw(17, subscriptionPurchase())
            .build()
    }

    private static func receiptWithPurchase(_ inAppPurchase: [UInt8]) -> [UInt8] {
        return ReceiptCreator.attributeSet()
            .string(0, "ProductionSandbox")
            .string(2, BUNDLE_ID)
            .date(12, RECEIPT_CREATION_DATE)
            .raw(17, inAppPurchase)
            .build()
    }

    private static func consumablePurchase() -> [UInt8] {
        return ReceiptCreator.attributeSet()
            .integer(1701, 1)
            .string(1702, CONSUMABLE_PRODUCT_ID)
            .string(1703, "70000000000001")
            .date(1704, CONSUMABLE_PURCHASE_DATE)
            .string(1705, "70000000000001")
            .date(1706, CONSUMABLE_ORIGINAL_PURCHASE_DATE)
            .date(1708, "")
            .integer(1711, 42)
            .date(1712, "")
            .integer(1719, 0)
            .raw(1799, UNKNOWN_IN_APP_ATTRIBUTE_VALUE)
            .build()
    }

    private static func subscriptionPurchase() -> [UInt8] {
        return ReceiptCreator.attributeSet()
            .integer(1701, 1)
            .string(1702, SUBSCRIPTION_PRODUCT_ID)
            .string(1703, "70000000000002")
            .date(1704, SUBSCRIPTION_PURCHASE_DATE)
            .string(1705, "70000000000002")
            .date(1706, SUBSCRIPTION_PURCHASE_DATE)
            .date(1708, SUBSCRIPTION_EXPIRES_DATE)
            .integer(1711, 12345)
            .date(1712, SUBSCRIPTION_CANCELLATION_DATE)
            .integer(1719, 1)
            .build()
    }

    private func validReceipt(_ result: VerificationResult<AppReceipt>) throws -> AppReceipt {
        switch result {
        case .valid(let receipt):
            return receipt
        case .invalid(let error):
            XCTFail("Expected a valid receipt, got \(error)")
            throw XCTSkip("Expected a valid receipt, got \(error)")
        }
    }

    private func assertInvalid<T>(_ expected: VerificationError, _ result: VerificationResult<T>) {
        switch result {
        case .valid(_):
            XCTAssert(false)
        case .invalid(let error):
            XCTAssertEqual(expected, error)
        }
    }

    private func encode(_ receipt: Data) -> String {
        return receipt.base64EncodedString()
    }

    private func derEncodedUTF8String(_ value: String) -> Data {
        var serializer = DER.Serializer()
        try! serializer.serialize(ASN1UTF8String(value))
        return Data(serializer.serializedBytes)
    }

    private func rfc3339(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    private func indexOf(_ haystack: Data, _ needle: [UInt8]) throws -> Data.Index {
        guard let range = haystack.range(of: Data(needle)) else {
            throw XCTSkip("Expected bytes not found in the receipt")
        }
        return range.lowerBound
    }
}
