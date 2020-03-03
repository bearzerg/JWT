import XCTest

import JWTTests

var tests = [XCTestCaseEntry]()
tests += JWTTests.allTests()
XCTMain(tests)
