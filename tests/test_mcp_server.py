"""
Unit tests for the TLS MCP Server

These tests verify that our MCP server functions work correctly:
1. Tools are listed properly
2. Certificate fetching works 
3. Certificate analysis works
4. Certificate linting works
5. Error handling works properly
"""

import pytest
import asyncio
import ssl
import socket
from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path

# Import our MCP server functions
from tls_mcp_server.main import (
    list_tools,
    call_tool,
    fetch_certificate,
    server
)

# Sample certificate for testing (Google's cert)
SAMPLE_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIEXzCCA0egAwIBAgIRALdEK2HlE3F/7XfVF6WTN58wDQYJKoZIhvcNAQELBQAw
RzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkdlb1RydXN0IEluYy4xHzAdBgNVBAMT
Fkdlb1RydXN0IFJhcGlkU1NMIENBMB4XDTI0MDEyNDA4MjUyNVoXDTI1MDEyNDA4
MjUyNFowFjEUMBIGA1UEAwwLKi5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEI8YCDQf6jAD9fIcF7n/8C3hQGk+Ym5h3VpVPUjK7dNbLsGWQJF3s
zGCQOCh9Lb0rJm0XfNkEHMKp8BYHlQw6/KOCAuwwggLoMB0GA1UdJQQWMBQGCCsG
AQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQN4B3y0L2K
2v1eP7VjJ3xNPfzWVjAfBgNVHSMEGDAWgBSxE/8p8WOHXqBOG2b3GRYd+3XNQTCB
2AYIKwYBBQUHAQEEgcswgcgwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLmdlb3Ry
dXN0LmNvbS8wgZ0GCCsGAQUFBzACgZCGgY1odHRwOi8vY2VydHMuZ2VvdHJ1c3Qu
Y29tL2NlcnRzL2dlb3RydXN0cmFwaWRzc2xjYS5jcnQwgbYGA1UdEQSBrjCBq4IL
Ki5nb29nbGUuY29tggxhcGkuZ29vZ2xlLmNvbYIOYXBpcy5nb29nbGUuY29tggwq
Lmdvb2dsZS5jb22CDSoueW91dHViZS5jb22CCnlvdXR1YmUuY29tMAwGA1UdEwEB
/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAE5m3Qp9FdNf+gPf6yCbCHsxP8jNUJOG
k1H3aeFHzTi2H8c7tQKlCpKJ7KRw5o7vKn9B1vZJ7k4J3+hRYl8hP7kRn/ELdCCl
9+5Q3nG9W3uOtB7DJb2k9wCjBZzP4E8KUJ7rZlxEMqK6m8k7l9m3xkJGT5qGhVxf
qP8wGlxF4H5Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G
4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y
4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4H8Y4p8Y4qPt5G4
-----END CERTIFICATE-----"""


class TestMCPServer:
    """Test class for MCP Server functionality"""

    @pytest.mark.asyncio
    async def test_list_tools(self):
        """Test that list_tools returns the expected tools"""
        tools = await list_tools()
        
        # Should have exactly 1 tool now (fetch_certificate with options)
        assert len(tools) == 1
        
        # Check tool name
        tool = tools[0]
        assert tool.name == "fetch_certificate"
        
        # Check that tool has required fields
        assert hasattr(tool, 'name')
        assert hasattr(tool, 'description')
        assert hasattr(tool, 'inputSchema')
        assert tool.description is not None
        assert len(tool.description) > 0
        
        # Check input schema has the new options
        schema = tool.inputSchema
        properties = schema["properties"]
        assert "hostname" in properties
        assert "port" in properties
        assert "include_pem" in properties
        assert "analyze" in properties
        assert "lint" in properties
        assert "use_openssl" in properties
        assert "analyze_ciphers" in properties
        assert "cipher_scan_type" in properties

    @pytest.mark.asyncio
    async def test_call_tool_unknown(self):
        """Test calling an unknown tool returns error"""
        result = await call_tool("unknown_tool", {})
        
        assert len(result) == 1
        assert result[0].type == "text"
        assert "Unknown tool" in result[0].text

    @pytest.mark.asyncio
    async def test_fetch_certificate_quick_analysis(self):
        """Test certificate fetching with quick analysis (default)"""
        with patch('tls_mcp_server.main._fetch_raw_certificate') as mock_fetch, \
             patch('tls_mcp_server.main._is_openssl_available') as mock_openssl_check, \
             patch('tls_mcp_server.main._analyze_with_cryptography') as mock_analyze:
            
            # Setup mocks
            mock_fetch.return_value = SAMPLE_CERT_PEM
            mock_openssl_check.return_value = False  # Force use of cryptography
            mock_analyze.return_value = "Mock analysis results"
            
            # Test the function with default options (quick analysis)
            result = await fetch_certificate({"hostname": "example.com"})
            
            # Verify results
            assert len(result) == 1
            assert result[0].type == "text"
            assert "Certificate Analysis for example.com:443" in result[0].text
            assert "Mock analysis results" in result[0].text
            
            # Verify mocks were called correctly
            mock_fetch.assert_called_once_with("example.com", 443)
            mock_analyze.assert_called_once_with(SAMPLE_CERT_PEM, "quick")

    @pytest.mark.asyncio
    async def test_fetch_certificate_with_detailed_analysis(self):
        """Test certificate fetching with detailed analysis"""
        with patch('tls_mcp_server.main._fetch_raw_certificate') as mock_fetch, \
             patch('tls_mcp_server.main._is_openssl_available') as mock_openssl_check, \
             patch('tls_mcp_server.main._analyze_with_openssl') as mock_openssl_analyze:
            
            # Setup mocks
            mock_fetch.return_value = SAMPLE_CERT_PEM
            mock_openssl_check.return_value = True  # OpenSSL available
            mock_openssl_analyze.return_value = "Detailed OpenSSL analysis"
            
            # Test with detailed analysis
            result = await fetch_certificate({
                "hostname": "example.com", 
                "analyze": "detailed",
                "use_openssl": True
            })
            
            # Verify results
            assert len(result) == 1
            assert result[0].type == "text"
            assert "Certificate Analysis for example.com:443" in result[0].text
            assert "Detailed OpenSSL analysis" in result[0].text
            
            # Verify OpenSSL was used
            mock_openssl_analyze.assert_called_once_with(SAMPLE_CERT_PEM, "detailed")

    @pytest.mark.asyncio
    async def test_fetch_certificate_with_lint(self):
        """Test certificate fetching with zlint"""
        with patch('tls_mcp_server.main._fetch_raw_certificate') as mock_fetch, \
             patch('tls_mcp_server.main._analyze_with_cryptography') as mock_analyze, \
             patch('tls_mcp_server.main._run_zlint') as mock_zlint:
            
            # Setup mocks
            mock_fetch.return_value = SAMPLE_CERT_PEM
            mock_analyze.return_value = "Quick analysis"
            mock_zlint.return_value = "Zlint results"
            
            # Test with linting enabled
            result = await fetch_certificate({
                "hostname": "example.com",
                "lint": True
            })
            
            # Verify results
            assert len(result) == 1
            assert result[0].type == "text"
            assert "Certificate Analysis for example.com:443" in result[0].text
            assert "Quick analysis" in result[0].text
            assert "Zlint results" in result[0].text
            
            # Verify zlint was called
            mock_zlint.assert_called_once_with(SAMPLE_CERT_PEM)

    @pytest.mark.asyncio
    async def test_fetch_certificate_with_pem_output(self):
        """Test certificate fetching with PEM output included"""
        with patch('tls_mcp_server.main._fetch_raw_certificate') as mock_fetch, \
             patch('tls_mcp_server.main._analyze_with_cryptography') as mock_analyze:
            
            # Setup mocks
            mock_fetch.return_value = SAMPLE_CERT_PEM
            mock_analyze.return_value = "Analysis results"
            
            # Test with PEM output included
            result = await fetch_certificate({
                "hostname": "example.com",
                "include_pem": True
            })
            
            # Verify results
            assert len(result) == 1
            assert result[0].type == "text"
            response_text = result[0].text
            assert "Certificate Analysis for example.com:443" in response_text
            assert "Analysis results" in response_text
            assert "Raw PEM Certificate:" in response_text
            assert SAMPLE_CERT_PEM in response_text

    @pytest.mark.asyncio
    async def test_fetch_certificate_no_analysis(self):
        """Test certificate fetching with no analysis"""
        with patch('tls_mcp_server.main._fetch_raw_certificate') as mock_fetch:
            
            # Setup mocks
            mock_fetch.return_value = SAMPLE_CERT_PEM
            
            # Test with no analysis
            result = await fetch_certificate({
                "hostname": "example.com",
                "analyze": "none",
                "include_pem": True
            })
            
            # Verify results
            assert len(result) == 1
            assert result[0].type == "text"
            response_text = result[0].text
            assert "Certificate Analysis for example.com:443" in response_text
            assert "Raw PEM Certificate:" in response_text
            assert SAMPLE_CERT_PEM in response_text

    @pytest.mark.asyncio
    async def test_fetch_certificate_connection_error(self):
        """Test certificate fetching with connection error"""
        with patch('tls_mcp_server.main._fetch_raw_certificate') as mock_fetch:
            mock_fetch.side_effect = ConnectionError("Connection refused")
            
            result = await fetch_certificate({"hostname": "nonexistent.example", "port": 443})
            
            assert len(result) == 1
            assert result[0].type == "text"
            assert "Failed to fetch certificate" in result[0].text
            assert "Connection refused" in result[0].text

    @pytest.mark.asyncio
    async def test_fetch_certificate_with_cipher_analysis(self):
        """Test certificate fetching with cipher analysis"""
        with patch('tls_mcp_server.main._fetch_raw_certificate') as mock_fetch, \
             patch('tls_mcp_server.main._analyze_with_cryptography') as mock_analyze, \
             patch('tls_mcp_server.main._analyze_cipher_suites') as mock_ciphers:
            
            # Setup mocks
            mock_fetch.return_value = SAMPLE_CERT_PEM
            mock_analyze.return_value = "Certificate analysis"
            mock_ciphers.return_value = "Cipher analysis results"
            
            # Test with cipher analysis enabled
            result = await fetch_certificate({
                "hostname": "example.com",
                "analyze_ciphers": True,
                "cipher_scan_type": "quick"
            })
            
            # Verify results
            assert len(result) == 1
            assert result[0].type == "text"
            response_text = result[0].text
            assert "Certificate Analysis for example.com:443" in response_text
            assert "Certificate analysis" in response_text
            assert "Cipher analysis results" in response_text
            
            # Verify cipher analysis was called
            mock_ciphers.assert_called_once_with("example.com", 443, "quick")

    @pytest.mark.asyncio 
    async def test_call_tool_routing(self):
        """Test that call_tool correctly routes to fetch_certificate function"""
        # Test fetch_certificate routing
        with patch('tls_mcp_server.main.fetch_certificate') as mock_fetch:
            mock_fetch.return_value = [MagicMock(type="text", text="mocked")]
            
            result = await call_tool("fetch_certificate", {"hostname": "test.com"})
            mock_fetch.assert_called_once_with({"hostname": "test.com"})

    def test_server_instance(self):
        """Test that server instance is created correctly"""
        # Verify the server is created with correct name
        assert server.name == "tls-mcp-server"
        
        # Verify server is a proper MCP server instance
        from mcp.server import Server
        assert isinstance(server, Server)


if __name__ == "__main__":
    pytest.main([__file__])