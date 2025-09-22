🧪 XSS SCANNER TEST CODE SAMPLES
================================

Copy and paste these code samples into your XSS Scanner to test its detection capabilities.

🚨 HIGH-RISK VULNERABILITIES
===========================

1. Direct innerHTML Assignment (Most Common)
-------------------------------------------
<div id="content"></div>
<script>
var userInput = '<script>alert("XSS Attack!")</script><img src=x onerror=alert("XSS")>';
document.getElementById('content').innerHTML = userInput;
</script>

2. document.write() Injection
----------------------------
<script>
var userInput = '<img src=x onerror=alert("XSS via document.write")>';
document.write('<div>' + userInput + '</div>');
</script>

3. eval() Function (Very Dangerous)
----------------------------------
<script>
var userCode = 'alert("XSS via eval")';
eval(userCode);
</script>

4. Dynamic Script Tag Creation
------------------------------
<script>
var userInput = '<script>alert("Dynamic script injection")</script>';
var script = document.createElement('script');
script.text = userInput;
document.body.appendChild(script);
</script>

⚠️ MEDIUM-RISK VULNERABILITIES
==============================

5. Event Handler Injection
-------------------------
<button onclick="alert(userInput)">Click me</button>
<script>
var userInput = 'XSS'; // This would be user-controlled in real scenario
</script>

6. JavaScript Protocol in Links
-------------------------------
<a href="javascript:alert('XSS via javascript protocol')">Malicious Link</a>

7. Dynamic src Attribute
-----------------------
<script>
var userInput = 'javascript:alert("XSS")';
document.querySelector('img').src = userInput;
</script>

8. Template Literal Injection
----------------------------
<div id="output"></div>
<script>
const userInput = '<script>alert("Template XSS")</script>';
document.getElementById('output').innerHTML = `<p>User input: ${userInput}</p>`;
</script>

🔍 ADVANCED ATTACK VECTORS
=========================

9. Location Hash Manipulation
-----------------------------
<script>
if (location.hash) {
    document.getElementById('content').innerHTML = location.hash.substring(1);
}
</script>

10. setTimeout with String
-------------------------
<script>
var userInput = 'alert("XSS via setTimeout")';
setTimeout(userInput, 1000);
</script>

11. Function Constructor
----------------------
<script>
var userInput = 'alert("XSS via Function constructor")';
var func = new Function(userInput);
func();
</script>

✅ SAFE CODE EXAMPLES
====================

12. Properly Sanitized Code
---------------------------
<div id="content"></div>
<script>
// Safe: Using textContent instead of innerHTML
var userInput = '<script>alert("XSS")</script>';
document.getElementById('content').textContent = userInput;
</script>

13. Commented Vulnerable Code
----------------------------
<script>
// This vulnerable code is commented out and should not be flagged
// document.getElementById('content').innerHTML = userInput;
// eval(userCode);
console.log('This is safe');
</script>

14. String Literals (Not Executable)
-----------------------------------
<script>
var codeString = 'document.getElementById("content").innerHTML = userInput;';
console.log('This is just a string:', codeString);
</script>

📊 COMPREHENSIVE TEST SUITE
==========================

15. Multiple Vulnerabilities in One File
---------------------------------------
<!DOCTYPE html>
<html>
<body>
    <div id="content1"></div>
    <div id="content2"></div>
    <img id="testImage">

    <script>
        // Multiple XSS vulnerabilities
        var userInput = '<script>alert("XSS1")</script>';
        var userCode = 'alert("XSS2")';

        // 1. innerHTML injection
        document.getElementById('content1').innerHTML = userInput;

        // 2. eval injection
        eval(userCode);

        // 3. document.write injection
        document.write('<div>' + userInput + '</div>');

        // 4. Dynamic script creation
        var script = document.createElement('script');
        script.text = 'alert("XSS3")';
        document.body.appendChild(script);

        // 5. Event handler injection
        button.onclick = function() { eval(userInput); };

        // 6. JavaScript protocol
        link.href = 'javascript:' + userInput;

        // 7. Dynamic src
        document.getElementById('testImage').src = userInput;
    </script>
</body>
</html>

🎯 QUICK TEST COMMANDS
=====================

Quick Test 1 - Basic innerHTML
------------------------------
document.getElementById('content').innerHTML = userInput;

Quick Test 2 - eval()
--------------------
eval(userInput);

Quick Test 3 - document.write()
-------------------------------
document.write(userInput);

Quick Test 4 - Safe Alternative
-------------------------------
document.getElementById('content').textContent = userInput;

📋 TESTING INSTRUCTIONS
======================

1. Copy any test case code above
2. Paste it into your XSS Scanner interface
3. Scan the code
4. Verify that:
   - Vulnerable code shows detected vulnerabilities
   - Safe code shows no vulnerabilities
   - Line numbers and descriptions are accurate

💡 Tip: Start with the "Multiple Vulnerabilities" test case to see how your scanner handles complex scenarios.

EXPECTED RESULTS
===============

Your scanner should detect:
- innerHTML assignments
- eval() function calls
- document.write() calls
- Dynamic script creation
- Event handler manipulation
- JavaScript protocol usage
- Template literal injections
- Location hash manipulation
- setTimeout with code strings
- Function constructor usage

The scanner should NOT flag:
- Commented out vulnerable code
- String literals containing vulnerable patterns
- Properly sanitized code using textContent
- Regular console.log statements
