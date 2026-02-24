//
//  KeychainSeedsQueryProviderTests.swift
//  PolkadotVaultTests
//
//  Created by Krzysztof Rodak on 29/08/2022.
//

@testable import PolkadotVault
import XCTest

// swiftlint:disable force_cast
final class KeychainSeedsQueryProviderTests: XCTestCase {
    private var subject: KeychainSeedsQueryProvider!

    override func setUp() {
        super.setUp()
        subject = KeychainSeedsQueryProvider()
    }

    func test_query_fetch_returnsExpectedValues() {
        // Given
        let queryType: KeychainSeedsQuery = .fetch
        let expectedSecClass = kSecClassGenericPassword as String
        let expectedMatchLimit = kSecMatchLimitAll as String
        let expectedReturnAttributes = true
        let expectedReturnData = false

        // When
        let result = subject.query(for: queryType) as! [String: Any]

        // Then
        XCTAssertEqual(result[kSecClass as String] as? String, expectedSecClass)
        XCTAssertEqual(result[kSecMatchLimit as String] as? String, expectedMatchLimit)
        XCTAssertEqual(result[kSecReturnAttributes as String] as? Bool, expectedReturnAttributes)
        XCTAssertEqual(result[kSecReturnData as String] as? Bool, expectedReturnData)
    }

    func test_query_deleteAll_returnsExpectedValues() {
        // Given
        let queryType: KeychainSeedsQuery = .deleteAll
        let expectedSecClass = kSecClassGenericPassword as String

        // When
        let result = subject.query(for: queryType) as! [String: Any]

        // Then
        XCTAssertEqual(result[kSecClass as String] as? String, expectedSecClass)
    }

    func test_query_check_returnsExpectedValues() {
        // Given
        let queryType: KeychainSeedsQuery = .check
        let expectedSecClass = kSecClassGenericPassword as String
        let expectedMatchLimit = kSecMatchLimitAll as String
        let expectedReturnData = true

        // When
        let result = subject.query(for: queryType) as! [String: Any]

        // Then
        XCTAssertEqual(result[kSecClass as String] as? String, expectedSecClass)
        XCTAssertEqual(result[kSecMatchLimit as String] as? String, expectedMatchLimit)
        XCTAssertEqual(result[kSecReturnData as String] as? Bool, expectedReturnData)
    }

    func test_query_search_returnsExpectedValues() {
        // Given
        let seedName = "account"
        let queryType: KeychainSeedsQuery = .search(seedName: seedName)
        let expectedSecClass = kSecClassGenericPassword as String
        let expectedMatchLimit = kSecMatchLimitOne as String
        let expectedReturnData = true

        // When
        let result = subject.query(for: queryType) as! [String: Any]

        // Then
        XCTAssertEqual(result[kSecClass as String] as? String, expectedSecClass)
        XCTAssertEqual(result[kSecMatchLimit as String] as? String, expectedMatchLimit)
        XCTAssertEqual(result[kSecAttrAccount as String] as? String, seedName)
        XCTAssertEqual(result[kSecReturnData as String] as? Bool, expectedReturnData)
    }

    func test_query_delete_returnsExpectedValues() {
        // Given
        let seedName = "account"
        let expectedSecClass = kSecClassGenericPassword as String
        let queryType: KeychainSeedsQuery = .delete(seedName: seedName)

        // When
        let result = subject.query(for: queryType) as! [String: Any]

        // Then
        XCTAssertEqual(result[kSecClass as String] as? String, expectedSecClass)
        XCTAssertEqual(result[kSecAttrAccount as String] as? String, seedName)
    }

    func test_query_restoreQuery_returnsExpectedValues() {
        // Given
        let seedName = "account"
        let finalSeedPhrase: Data! = "account".data(using: .utf8)
        let expectedSecClass = kSecClassGenericPassword as String
        let expectedAccessControl: SecAccessControl! = try? SimulatorAccessControlProvider()
            .accessControl() // it's fine to use it instead of mock, as it's just dedicated to be used on simulator
        let expectedReturnData = true
        let queryType: KeychainSeedsQuery = .restoreQuery(
            seedName: seedName,
            finalSeedPhrase: finalSeedPhrase,
            accessControl: expectedAccessControl
        )
        // When
        let result = subject.query(for: queryType) as! [String: Any]

        // Then
        XCTAssertEqual(result[kSecClass as String] as? String, expectedSecClass)
        let accessControl = result[kSecAttrAccessControl as String]
        XCTAssertNotNil(accessControl)
        XCTAssertTrue((accessControl as AnyObject) === (expectedAccessControl as AnyObject))
        XCTAssertEqual(result[kSecAttrAccount as String] as? String, seedName)
        XCTAssertEqual(result[kSecValueData as String] as? Data, finalSeedPhrase)
        XCTAssertEqual(result[kSecReturnData as String] as? Bool, expectedReturnData)
    }
}
