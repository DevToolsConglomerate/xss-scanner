#!/bin/bash
# XSS Scanner API Test Commands
# Run these curl commands to test your API endpoints

echo "🧪 XSS Scanner API Tests"
echo "========================"

# Test API Status
echo -e "\n1. Testing API Status:"
curl -X GET "http://localhost:8000/api/status" \
  -H "Content-Type: application/json"

# Test XSS Scanning
echo -e "\n\n2. Testing XSS Scan (Basic innerHTML):"
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{
    "code": "document.getElementById(\"content\").innerHTML = userInput;",
    "options": {
      "scan_type": "full",
      "severity_threshold": "medium"
    }
  }'

echo -e "\n\n3. Testing XSS Scan (Multiple vulnerabilities):"
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{
    "code": "<script>var userInput = \"<script>alert(1)</script>\"; document.getElementById(\"content\").innerHTML = userInput; eval(\"alert(2)\"); document.write(\"<img src=x onerror=alert(3)>\");</script>",
    "options": {
      "scan_type": "full",
      "severity_threshold": "low"
    }
  }'

echo -e "\n\n4. Testing XSS Scan (Safe code):"
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{
    "code": "<script>document.getElementById(\"content\").textContent = userInput; console.log(\"safe\");</script>",
    "options": {
      "scan_type": "full",
      "severity_threshold": "medium"
    }
  }'

echo -e "\n\n5. Testing Invalid API Key:"
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: invalid-key" \
  -d '{
    "code": "document.getElementById(\"content\").innerHTML = userInput;",
    "options": {
      "scan_type": "full",
      "severity_threshold": "medium"
    }
  }'

echo -e "\n\n"===================="
echo "📝 Notes:"
echo "- Replace 'your-api-key-here' with your actual API key"
echo "- Make sure your API server is running on localhost:8000"
echo "- Check the JSON responses for vulnerability details"
echo "- Use the test_code_samples.txt file for more test cases"
