#!/usr/bin/env python3
"""
Comprehensive test suite for XSS Scanner with security and performance tests
"""

import pytest
import time
from utils_fixed import scanner
from models_fixed import XSSScanRequest

def test_vulnerable_code():
    """Test the scanner with various vulnerable code snippets"""

    test_cases = [
        {
            "name": "innerHTML assignment",
            "code": '<div id="content"></div>\n<script>\ndocument.getElementById("content").innerHTML = userInput;\n</script>',
            "expected_vulnerabilities": 1
        },
        {
            "name": "document.write call",
            "code": '<script>\nvar userInput = "<script>alert(\'xss\')</script>";\ndocument.write(userInput);\n</script>',
            "expected_vulnerabilities": 1
        },
        {
            "name": "eval function",
            "code": '<script>\nvar code = "alert(\'xss\')";\neval(code);\n</script>',
            "expected_vulnerabilities": 1
        },
        {
            "name": "script tag injection",
            "code": '<div>\n<script>\n// This is a comment\nalert("safe");\n</script>\n<script src="malicious.js"></script>\n</div>',
            "expected_vulnerabilities": 1
        },
        {
            "name": "event handler",
            "code": '<button onclick="alert(userInput)">Click me</button>',
            "expected_vulnerabilities": 1
        },
        {
            "name": "javascript protocol",
            "code": '<a href="javascript:alert(\'xss\')">Link</a>',
            "expected_vulnerabilities": 1
        },
        {
            "name": "safe code",
            "code": '<div>Hello World</div>\n<script>\nconsole.log("safe");\n</script>',
            "expected_vulnerabilities": 0
        },
        {
            "name": "template literals",
            "code": '<div id="output"></div>\n<script>\nconst userInput = "malicious";\ndocument.getElementById("output").innerHTML = `<p>${userInput}</p>`;\n</script>',
            "expected_vulnerabilities": 2  # innerHTML + template literal
        }
    ]

    print("🧪 Testing XSS Scanner")
    print("=" * 50)

    passed = 0
    total = len(test_cases)

    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case['name']}")
        print("-" * 30)

        start_time = time.time()
        result = scanner.scan_code(test_case['code'])
        end_time = time.time()

        found = result['vulnerabilities_found']
        expected = test_case['expected_vulnerabilities']

        print(f"Code:\n{test_case['code']}")
        print(f"\nExpected vulnerabilities: {expected}")
        print(f"Found vulnerabilities: {found}")
        print(f"Scan time: {end_time - start_time".3f"} seconds")

        if found > 0:
            print("\nVulnerabilities found:")
            for vuln in result['vulnerabilities'][:3]:  # Show first 3
                print(f"  - Line {vuln['line']}: {vuln['vulnerability_type']}")
                print(f"    {vuln['description']}")

        if found == expected:
            print("✅ PASSED")
            passed += 1
        else:
            print("❌ FAILED")

    print("\n" + "=" * 50)
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Scanner is working correctly.")
    else:
        print("⚠️  Some tests failed. Please review the scanner logic.")

    return passed == total

def test_scanner_performance():
    """Test scanner performance with large code samples"""
    print("\n🕐 Testing Scanner Performance")
    print("=" * 30)

    # Test with large code sample
    large_code = """
    <html>
    <head><title>Test</title></head>
    <body>
    <div id="content1">Safe content</div>
    <div id="content2">Safe content</div>
    <div id="content3">Safe content</div>
    <script>
    // This is safe
    console.log("safe");
    document.getElementById("content1").innerHTML = userInput; // Vulnerable
    document.getElementById("content2").innerHTML = safeInput; // Safe
    document.getElementById("content3").innerHTML = userInput; // Vulnerable
    </script>
    </body>
    </html>
    """ * 100  # Repeat 100 times

    start_time = time.time()
    result = scanner.scan_code(large_code)
    end_time = time.time()

    print(f"Code size: {len(large_code)} characters")
    print(f"Vulnerabilities found: {result['vulnerabilities_found']}")
    print(f"Scan time: {end_time - start_time".3f"} seconds")

    # Performance should be reasonable (under 5 seconds for this size)
    if end_time - start_time < 5.0:
        print("✅ Performance test PASSED")
        return True
    else:
        print("❌ Performance test FAILED - too slow")
        return False

def test_input_validation():
    """Test input validation"""
    print("\n🔒 Testing Input Validation")
    print("=" * 30)

    # Test empty code
    try:
        result = scanner.scan_code("")
        print("❌ Empty code test FAILED - should have been rejected")
        return False
    except Exception as e:
        print(f"✅ Empty code test PASSED - properly rejected: {e}")

    # Test oversized code
    large_code = "a" * 100001  # Over the limit
    try:
        result = scanner.scan_code(large_code)
        print("❌ Oversized code test FAILED - should have been rejected")
        return False
    except Exception as e:
        print(f"✅ Oversized code test PASSED - properly rejected: {e}")

    return True

def test_regex_accuracy():
    """Test regex pattern accuracy to avoid false positives"""
    print("\n🎯 Testing Regex Accuracy")
    print("=" * 30)

    test_cases = [
        {
            "name": "Commented vulnerable code",
            "code": '<script>\n// document.getElementById("content").innerHTML = userInput;\nconsole.log("safe");\n</script>',
            "expected_vulnerabilities": 0
        },
        {
            "name": "String literal containing vulnerable pattern",
            "code": '<script>\nvar code = "document.getElementById(\'content\').innerHTML = userInput;";\nconsole.log(code);\n</script>',
            "expected_vulnerabilities": 0
        },
        {
            "name": "Actual vulnerable code",
            "code": '<script>\ndocument.getElementById("content").innerHTML = userInput;\n</script>',
            "expected_vulnerabilities": 1
        }
    ]

    passed = 0
    for test_case in test_cases:
        result = scanner.scan_code(test_case['code'])
        found = result['vulnerabilities_found']
        expected = test_case['expected_vulnerabilities']

        if found == expected:
            print(f"✅ {test_case['name']}: PASSED")
            passed += 1
        else:
            print(f"❌ {test_case['name']}: FAILED (found {found}, expected {expected})")

    return passed == len(test_cases)

def run_all_tests():
    """Run all test suites"""
    print("🚀 Running Comprehensive XSS Scanner Tests")
    print("=" * 60)

    tests = [
        ("Basic Functionality", test_vulnerable_code),
        ("Performance", test_scanner_performance),
        ("Input Validation", test_input_validation),
        ("Regex Accuracy", test_regex_accuracy)
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name}: CRASHED - {e}")
            results.append((test_name, False))

    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)

    passed = 0
    total = len(results)

    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
        if result:
            passed += 1

    print(f"\nOverall: {passed}/{total} test suites passed")

    if passed == total:
        print("🎉 All tests passed! The scanner is ready for production.")
        return True
    else:
        print("⚠️  Some tests failed. Please review and fix the issues.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
