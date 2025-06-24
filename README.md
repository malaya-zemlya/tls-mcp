# TLS MCP Server

A **Model Context Protocol (MCP)** server that provides a unified, user-friendly tool for TLS certificate analysis. No more copying PEM data between functions - everything happens in one clean interface!
This tool has been written entirely via Claude Code, as a fun learning project.

## 🚀 Features

- **All-in-One Interface**: Single tool with flexible options for any certificate analysis need
- **Smart Analysis**: Automatically uses OpenSSL when available, falls back to Python cryptography
- **Certificate Expiration Monitoring**: Automatic expiration checking with human-friendly warnings
- **Cipher Suite Analysis**: Comprehensive TLS cipher suite and version support testing
- **Security Grading**: Automated security assessment with grades from A+ to F
- **Flexible Options**: Choose quick/detailed analysis, include/exclude PEM, enable/disable linting
- **Zero PEM Copying**: Analysis happens automatically without manual certificate handling
- **Comprehensive Testing**: Full test coverage with unit, integration, and real-world tests

## 🛠️ Tool Provided

### `fetch_certificate` - All-in-One Certificate Analysis
Fetches and analyzes TLS certificates with flexible options - no need to copy PEM data between tools!

**Parameters:**
- `hostname` (required): Website hostname (e.g., "google.com")
- `port` (optional): Port number (default: 443)
- `include_pem` (optional): Include raw PEM certificate in output (default: false)
- `analyze` (optional): Analysis level - "none", "quick", or "detailed" (default: "quick")
- `lint` (optional): Run zlint compliance checking (default: false)
- `use_openssl` (optional): Use OpenSSL for analysis when available (default: true)
- `analyze_ciphers` (optional): Analyze supported cipher suites and TLS versions (default: false)
- `cipher_scan_type` (optional): Type of cipher scan - "quick" or "full" (default: "quick")

**Analysis Options:**
- **Quick Analysis**: Essential certificate info (subject, issuer, validity, SANs)
- **Detailed Analysis**: Full certificate details including extensions and key info
- **Expiration Monitoring**: Automatic expiration checking with smart warnings:
  - ✅ Valid certificates show time until expiration
  - 🟡 Certificates expiring within 30 days get yellow warning
  - ⚠️ Certificates expiring within 7 days get urgent warning
  - 🔴 Expired certificates show time since expiration
  - ⏳ Future-valid certificates show time until validity
- **OpenSSL vs Cryptography**: Automatically uses OpenSSL if available, falls back to Python cryptography

**Examples:**
- `{"hostname": "google.com"}` - Quick analysis only
- `{"hostname": "github.com", "analyze": "detailed", "lint": true}` - Detailed analysis + zlint
- `{"hostname": "badssl.com", "analyze": "none", "include_pem": true}` - Just fetch PEM

## 📋 Prerequisites

- **Python 3.13+**
- **zlint** (for certificate linting)
- **OpenSSL** (for certificate operations)

### Install zlint
```bash
# macOS
brew install zlint

# Linux
go install github.com/zmap/zlint/v3/cmd/zlint@latest

# Or download from releases: https://github.com/zmap/zlint/releases
```

## 🔧 Installation

1. **Clone and setup the project:**
```bash
git clone <repository-url>
cd tls-mcp
python3.13 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

2. **Install development dependencies (optional):**
```bash
pip install -e ".[dev]"
```

3. **Run tests to verify installation:**
```bash
pytest tests/ -v
```

## ⚙️ Configuration

Add the following to your Claude Desktop configuration file:

**Location:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tls-mcp-server": {
      "command": "/path/to/your/tls-mcp/venv/bin/python",
      "args": [
        "/path/to/your/tls-mcp/tls_mcp_server/main.py"
      ],
      "env": {
        "PYTHONPATH": "/path/to/your/tls-mcp"
      }
    }
  }
}
```

**Replace `/path/to/your/tls-mcp` with your actual project path.**

## 🚦 Usage Examples

After configuration, restart Claude Desktop and try these commands:

### Quick Certificate Analysis (Default)
```
"Analyze the certificate for github.com"
```

### Detailed Analysis with Compliance Check
```
"Do a detailed analysis of google.com's certificate and run zlint on it"
```

### Just Fetch Certificate (No Analysis)
```
"Get me the raw PEM certificate for badssl.com"
```

### Compare Multiple Certificates
```
"Use the TLS certificate tool to analyze both google.com and github.com, then compare their key differences"
```

### Security Assessment
```
"Use the TLS certificate tool to check if example.com uses secure certificate practices with full analysis and linting"
```

### Cipher Suite Analysis
```
"Use the TLS certificate tool to analyze the cipher suites supported by github.com and give me a security assessment"
```

### Comprehensive Security Analysis
```
"Use the TLS certificate tool to do a full security analysis of google.com including cipher suites, TLS versions, and certificate compliance"
```

**Key Benefits:**
- ✅ **No PEM copying** - Analysis happens automatically
- ✅ **Flexible options** - Choose what info you need
- ✅ **Smart defaults** - Works great out of the box
- ✅ **OpenSSL integration** - Uses the best available tools

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests (including slow integration tests)
pytest tests/ -v

# Run only fast tests (excludes slow integration tests that require internet)
pytest tests/ -m "not slow" -v

# Run with coverage
pytest tests/ --cov=tls_mcp_server --cov-report=term-missing

# Run only unit tests
pytest tests/test_mcp_server.py -v

# Run only basic integration tests
pytest tests/test_integration.py -v

# Run real-world integration tests (requires internet and zlint)
pytest tests/test_google_integration.py -v
```

### Test Coverage
- **Unit Tests**: Test the new unified interface with mocked dependencies
- **Cipher Analysis Tests**: Test cipher categorization, TLS version detection, and security grading
- **Expiration Check Tests**: Test certificate validity checking, duration formatting, and timezone handling
- **Basic Integration Tests**: Test server registration and tool options
- **Real-World Integration Tests**: Test full workflow with live Google certificate  
- **Error Handling**: Test various failure scenarios
- **Current Coverage**: 34 passing tests with comprehensive coverage

## 📁 Project Structure

```
tls-mcp/
├── tls_mcp_server/
│   ├── __init__.py          # Package initialization
│   └── main.py              # MCP server implementation
├── tests/
│   ├── __init__.py              # Test package
│   ├── test_mcp_server.py       # Unit tests
│   ├── test_cipher_analysis.py  # Cipher analysis tests
│   ├── test_expiration_check.py # Expiration checking tests
│   └── test_integration.py      # Integration tests
├── pyproject.toml           # Project configuration
├── pytest.ini              # Test configuration
└── README.md               # This file
```

## 🔍 Architecture

The server is built using the **MCP Python SDK** with a modern, user-friendly design:

1. **Single Tool Interface**: One `fetch_certificate` tool with flexible options
2. **Smart Analysis**: Automatically chooses OpenSSL or Python cryptography
3. **Async Operations**: All operations are asynchronous for better performance
4. **Error Handling**: Comprehensive error handling with graceful fallbacks
5. **Modular Helpers**: Internal helper functions for different analysis methods
6. **No PEM Juggling**: Analysis happens automatically without manual PEM copying

## 🚨 Security Considerations

- Certificates are processed locally - no data is sent to external services
- Network connections use standard SSL/TLS libraries
- Temporary files are cleaned up after zlint operations
- Error messages don't expose sensitive system information

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `pytest tests/ -v`
5. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details.

## 🆘 Troubleshooting

### Common Issues

**"zlint command not found"**
- Install zlint using the instructions above
- Verify it's in your PATH: `which zlint`

**"Failed to fetch certificate"**
- Check your internet connection
- Verify the hostname is correct
- Some servers may block automated requests

**"MCP server not appearing in Claude"**
- Verify the configuration file path is correct
- Check that Python path in config points to your virtual environment
- Restart Claude Desktop after configuration changes

### Debug Mode

Enable debug logging by setting the environment variable:
```bash
export PYTHONPATH="/path/to/tls-mcp"
python tls_mcp_server/main.py
```

## 🏷️ Version History

- **v0.2.1**: Added certificate expiration monitoring with human-friendly warnings and timezone handling
- **v0.2.0**: Major interface redesign with unified `fetch_certificate` tool, OpenSSL integration, cipher suite analysis, security grading
- **v0.1.0**: Initial release with basic certificate fetching, analysis, and linting
