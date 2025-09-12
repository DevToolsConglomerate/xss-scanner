#!/usr/bin/env python3
"""
Test script for XSS Scanner
"""

from utils import scanner

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

        result = scanner.scan_code(test_case['code'])

        found = result['vulnerabilities_found']
        expected = test_case['expected_vulnerabilities']

        print(f"Code:\n{test_case['code']}")
        print(f"\nExpected vulnerabilities: {expected}")
        print(f"Found vulnerabilities: {found}")

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

if __name__ == "__main__":
    test_vulnerable_code()
