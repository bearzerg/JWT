import XCTest
@testable import JWT

final class JWTTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(JWT().token, nil)
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
