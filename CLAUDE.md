# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing
```bash
# Run all tests
pytest tests/ -v

# Run fast tests only (skip internet-dependent tests)
pytest tests/ -m "not slow" -v

# Run specific test files
pytest tests/test_mcp_server.py -v
pytest tests/test_cipher_analysis.py -v
pytest tests/test_integration.py -v

# Run with coverage
pytest tests/ --cov=tls_mcp_server --cov-report=term-missing
```

### Development Tools
```bash
# Install development dependencies
pip install -e ".[dev]"

# Code formatting
black tls_mcp_server/ tests/

# Linting
ruff check tls_mcp_server/ tests/

# Type checking
mypy tls_mcp_server/
```

### Running the MCP Server
```bash
# For testing/development
python tls_mcp_server/main.py

# Via entry point (after installation)
tls-mcp-server
```

## Architecture Overview

This is a **Model Context Protocol (MCP) server** that provides TLS certificate analysis capabilities to Claude. The architecture follows a single unified tool design to avoid PEM data copying between separate functions.

### Core Components

**Single Tool Interface (`fetch_certificate`)**
- Unified function that handles certificate fetching, analysis, linting, and cipher analysis
- Flexible parameter system allows selective feature activation
- Returns structured text output with all requested analysis

**Analysis Backends**
- **OpenSSL Integration**: Primary analysis engine using subprocess calls to `openssl s_client`
- **Python Cryptography**: Fallback analysis using the `cryptography` library
- **zlint**: External compliance checking tool

**Cipher Suite Analysis**
- TLS version detection (1.0, 1.1, 1.2, 1.3)
- Individual cipher suite testing
- Security categorization (secure/good/weak/deprecated)
- Automated security grading (A+ to F)

### Key Design Decisions

**Output Redirection Handling**: OpenSSL's `-brief` flag sends output to STDERR, not STDOUT. All subprocess parsing must check both `result.stdout + result.stderr`.

**Timeout Management**: Uses Python's subprocess timeout instead of system `timeout` command (macOS compatibility).

**TLS 1.3 vs 1.2 Cipher Testing**: TLS 1.3 uses `-ciphersuites` flag, while TLS 1.2 and below use `-cipher` flag.

**Connection Termination**: All OpenSSL commands include `input='\n'` to immediately close connections and prevent hanging.

**Certificate Expiration Monitoring**: All certificate analysis automatically includes expiration checking with UTC timezone handling. Uses human-friendly duration formatting (e.g., "62 days", "3 hours") and provides smart warnings based on urgency.

## Prerequisites

- **Python 3.13+** (strict requirement)
- **OpenSSL** (for cipher analysis and certificate operations)
- **zlint** (for certificate compliance checking)

Install zlint:
```bash
# macOS
brew install zlint

# Linux
go install github.com/zmap/zlint/v3/cmd/zlint@latest
```

## Configuration for Claude Desktop

The server requires configuration in Claude Desktop at:
`~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tls-mcp-server": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/tls-mcp/tls_mcp_server/main.py"],
      "env": {
        "PYTHONPATH": "/path/to/tls-mcp"
      }
    }
  }
}
```

## Testing Strategy

**Unit Tests** (`test_mcp_server.py`): Mock external dependencies, test tool interface and parameter handling.

**Cipher Analysis Tests** (`test_cipher_analysis.py`): Test security categorization, TLS version detection, and grading algorithms with mocked subprocess calls.

**Expiration Check Tests** (`test_expiration_check.py`): Test certificate validity checking, duration formatting, timezone handling, and various expiration scenarios.

**Integration Tests** (`test_integration.py`): Test MCP server registration and basic functionality.

**Slow Tests**: Real-world tests requiring internet access and external tools. Skip with `-m "not slow"`.

## Important Implementation Notes

**Error Handling**: Certificate verification is disabled (`ssl.CERT_NONE`) to allow analysis of any certificate, including self-signed ones.

**Security Categorization**: Uses predefined cipher lists plus heuristic analysis for unknown ciphers.

**Performance**: Quick cipher scans test ~20 common ciphers, full scans can test 50+ ciphers with appropriate timeouts.

**Documentation**: See `OPENSSL-notes.md` for detailed OpenSSL integration findings and debugging insights from development.