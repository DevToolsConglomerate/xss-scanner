# XSS Scanner API

A fast, automated API to scan HTML and JavaScript code snippets for potential Cross-Site Scripting (XSS) vulnerabilities. Uses heuristic patterns to identify dangerous coding practices.

## 🚀 Features

- **Fast Scanning**: Built with FastAPI for high-performance analysis
- **Comprehensive Detection**: Scans for multiple XSS patterns including:
  - `innerHTML` assignments
  - `document.write()` calls
  - `eval()` function usage
  - Script tag injections
  - Inline event handlers
  - JavaScript protocol usage
- **RESTful API**: Simple HTTP endpoints for easy integration
- **Authentication**: Secure API key-based authentication
- **Cloud Deployment**: Ready for Vercel serverless deployment

## 📋 Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Running Locally](#running-locally)
- [API Documentation](#api-documentation)
- [Deployment](#deployment)
- [Usage Examples](#usage-examples)

## 🛠 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- MongoDB (for API key storage)
- Git

### Clone the Repository

```bash
git clone https://github.com/DevToolsConglomerate/xss-scanner
cd xss-scanner-api
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# MongoDB Configuration (optional - app runs in demo mode without it)
MONGODB_URI=mongodb://localhost:27017/your_database

# Stripe Configuration (for payments)
STRIPE_API_KEY=your_stripe_api_key
STRIPE_WEBHOOK_SECRET=your_webhook_secret

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-secret-key-here
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
```

**Note**: The application runs in demo mode without MongoDB, accepting any API key for testing purposes.

### Database Setup

1. Start MongoDB service
2. Create a database called `devtools_conglomerate`
3. Create a collection called `api_keys` with documents like:

```json
{
  "key": "your-api-key-here",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

## 🚀 Running Locally

### One-Command Setup

The application now serves both the API and the frontend from a single server:

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server (serves API + frontend)
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Access Points

- **Frontend**: `http://localhost:8000/index.html`
- **API**: `http://localhost:8000/scan`
- **API Documentation**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/`

### Features Available

- Landing page with demo scanner
- User signup/login with API key generation
- Full XSS scanning interface
- RESTful API for integrations

### Demo Mode

If MongoDB is not configured, the application runs in demo mode:
- Accepts any API key for scanning
- Stores user data in localStorage (browser-based)
- No database required for testing

## 📚 API Documentation

### Base URL
```
http://localhost:8000
```

### Authentication

All API requests require an API key in the header:
```
X-API-Key: your_api_key_here
```

### Endpoints

#### Health Check
- **GET** `/`
- **Description**: Check if the API is running
- **Response**:
```json
{
  "message": "XSS Scanner API is operational",
  "status": "success"
}
```

#### Scan Code for XSS
- **POST** `/scan`
- **Description**: Scan HTML/JavaScript code for XSS vulnerabilities
- **Headers**:
  ```
  Content-Type: application/json
  X-API-Key: your_api_key
  ```
- **Request Body**:
```json
{
  "code": "your HTML or JavaScript code here"
}
```
- **Response**:
```json
{
  "status": "success",
  "vulnerabilities_found": 2,
  "vulnerabilities": [
    {
      "line": 5,
      "vulnerability_type": "innerHTML_assignment",
      "snippet": "element.innerHTML = userInput",
      "confidence": "medium"
    },
    {
      "line": 10,
      "vulnerability_type": "eval_function_call",
      "snippet": "eval(userInput)",
      "confidence": "medium"
    }
  ],
  "message": "Scan completed. Found 2 potential vulnerabilities."
}
```

#### Stripe Webhook
- **POST** `/stripe-webhook`
- **Description**: Handle Stripe payment webhooks
- **Headers**:
  ```
  Content-Type: application/json
  Stripe-Signature: webhook_signature
  ```

## 🚀 Deployment

### Vercel Deployment

1. **Connect Repository**: Link your GitHub repository to Vercel
2. **Configure Build Settings**:
   - Build Command: `./build.sh`
   - Output Directory: `.`
   - Install Command: `pip install -r requirements.txt`
3. **Environment Variables**: Add your environment variables in Vercel dashboard
4. **Deploy**: Push to main branch or deploy manually

### Manual Deployment

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export MONGODB_URI="your_mongodb_uri"
export STRIPE_API_KEY="your_stripe_key"

# Run with production server
uvicorn main:app --host 0.0.0.0 --port 8000
```

## 💡 Usage Examples

### Python Example

```python
import requests

# API endpoint
url = "http://localhost:8000/scan"

# Headers
headers = {
    "Content-Type": "application/json",
    "X-API-Key": "your_api_key_here"
}

# Code to scan
payload = {
    "code": """
    <div id="content"></div>
    <script>
        var userInput = getQueryParam('input');
        document.getElementById('content').innerHTML = userInput;
        eval(userInput);
    </script>
    """
}

# Make request
response = requests.post(url, json=payload, headers=headers)
result = response.json()

print(f"Vulnerabilities found: {result['vulnerabilities_found']}")
for vuln in result['vulnerabilities']:
    print(f"Line {vuln['line']}: {vuln['vulnerability_type']} - {vuln['snippet']}")
```

### cURL Example

```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "code": "<script>eval(location.hash.slice(1))</script>"
  }'
```

### JavaScript Example

```javascript
const scanCode = async (code) => {
  const response = await fetch('http://localhost:8000/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'your_api_key_here'
    },
    body: JSON.stringify({ code })
  });

  const result = await response.json();
  console.log('Scan result:', result);
};

// Example usage
scanCode('<div innerHTML=userInput></div>');
```

## 🔧 Development

### Project Structure

```
xss-scanner/
├── main.py                 # Main FastAPI application
├── api/
│   └── vercel_bootstrap.py # Vercel deployment bootstrap
├── index.html             # Landing page
├── requirements.txt       # Python dependencies
├── build.sh              # Vercel build script
├── README.md             # This file
└── .env                  # Environment variables (create this)
```

### Code Quality

- Uses type hints for better code clarity
- Comprehensive error handling
- Modular function design
- Detailed documentation strings

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/your-username/xss-scanner-api/issues) page
2. Review the API documentation at `/docs`
3. Create a new issue with detailed information

## 🔄 Changelog

### Version 1.0.0
- Initial release
- Basic XSS scanning functionality
- FastAPI implementation
- Vercel deployment support
- API key authentication
