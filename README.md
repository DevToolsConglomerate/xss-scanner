# XSS Scanner API

A fast, automated API to scan HTML and JavaScript code snippets for potential Cross-Site Scripting (XSS) vulnerabilities. Uses heuristic patterns to identify dangerous coding practices.

## API Endpoint

`POST /scan`

### Request Body
```json
{
    "code": "your HTML or JavaScript code here"
}