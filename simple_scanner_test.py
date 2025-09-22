#!/usr/bin/env python3
"""
Simple XSS Scanner Test Script
Run this to test your scanner with various code samples
"""

def test_basic_vulnerabilities():
    """Test basic XSS vulnerabilities"""

    test_cases = [
        {
            "name": "Basic innerHTML XSS",
            "code": 'document.getElementById("content").innerHTML = userInput;',
            "expected": True
        },
        {
            "name": "eval() XSS",
            "code": "eval(userInput);",
            "expected": True
        },
        {
            "name": "document.write() XSS",
            "code": "document.write(userInput);",
            "expected": True
        },
        {
            "name": "Safe textContent",
            "code": 'document.getElementById("content").textContent = userInput;',
            "expected": False
        },
        {
            "name": "Commented vulnerable code",
            "code": "// document.getElementById('content').innerHTML = userInput;",
            "expected": False
        }
    ]

    print("🧪 XSS Scanner Test Results")
    print("=" * 40)

    for i, test in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test['name']}")
        print(f"Code: {test['code']}")
        print(f"Expected: {'VULNERABLE' if test['expected'] else 'SAFE'}")

        # Here you would call your scanner
        # result = scanner.scan_code(test['code'])

        print("Result: [Run your scanner here]")

    print("\n" + "=" * 40)
    print("💡 To use this with your scanner:")
    print("1. Import your scanner module")
    print("2. Replace the comment with: result = scanner.scan_code(test['code'])")
    print("3. Check if result['vulnerabilities_found'] > 0")

if __name__ == "__main__":
    test_basic_vulnerabilities()
