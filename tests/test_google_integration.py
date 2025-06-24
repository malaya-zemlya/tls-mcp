"""
Real-world integration test for TLS MCP Server

This test fetches a live certificate from www.google.com and runs all three tools:
1. fetch_certificate - Gets the actual certificate from Google
2. analyze_certificate - Parses the certificate details
3. lint_certificate - Runs zlint compliance checks

This is a slower test that requires internet connectivity and zlint installation.
"""

import pytest
import asyncio
from unittest.mock import patch

from tls_mcp_server.main import fetch_certificate


class TestGoogleIntegration:
    """Real-world integration tests using Google's certificate"""

    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_full_google_certificate_workflow(self):
        """
        End-to-end test: fetch Google's cert, analyze it, and lint it
        
        This test verifies:
        1. We can fetch a real certificate from www.google.com
        2. The certificate can be parsed and analyzed
        3. The certificate can be linted with zlint
        4. All operations complete without critical errors
        """
        
        # Fetch and analyze with the new unified interface
        print("\n🔍 Fetching and analyzing certificate from www.google.com...")
        result = await fetch_certificate({
            "hostname": "www.google.com", 
            "port": 443,
            "analyze": "detailed",
            "lint": True
        })
        
        # Verify operation succeeded
        assert len(result) == 1
        assert result[0].type == "text"
        
        result_text = result[0].text
        assert "Certificate Analysis for www.google.com:443" in result_text
        
        # Check for analysis content
        assert "google.com" in result_text.lower()  # Should be in subject or SAN
        
        # Check if analysis was included
        assert ("Analysis" in result_text or "Subject:" in result_text)
        
        print("✅ Certificate analysis completed successfully")
        print(f"   - Found Google domain reference")
        print(f"   - Analysis and lint results included")
        
        # Check if zlint ran
        if "zlint not installed" in result_text:
            pytest.skip("zlint not installed - skipping lint verification")
        elif "zlint timed out" in result_text:
            pytest.fail("zlint timed out - this shouldn't happen with Google's cert")
        else:
            print("✅ Certificate linting completed")
            # zlint results should be present
            assert ("Compliance Check" in result_text or "zlint" in result_text.lower())
        
        print("\n🎉 Full workflow completed successfully!")
        print("   - Certificate fetched from www.google.com")
        print("   - Certificate analyzed and parsed")
        print("   - Certificate linted for compliance")

    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_google_certificate_has_expected_properties(self):
        """
        Test that Google's certificate has expected security properties
        """
        
        # Fetch and analyze Google's certificate with detailed analysis
        result = await fetch_certificate({
            "hostname": "www.google.com", 
            "port": 443,
            "analyze": "detailed"
        })
        
        assert len(result) == 1
        analysis_text = result[0].text
        
        # Google should use modern security practices
        # Check for reasonable key size (Google typically uses ECDSA or RSA >= 2048)
        assert ("2048" in analysis_text or "256" in analysis_text or 
                "384" in analysis_text), "Google should use strong key sizes"
        
        # Check for modern signature algorithm (should not be MD5 or SHA1)
        assert "md5" not in analysis_text.lower(), "Should not use MD5"
        assert "sha1WithRSA" not in analysis_text, "Should not use SHA1 with RSA"
        
        # Should have Google domain reference
        assert "google.com" in analysis_text.lower(), "Should contain google.com"
        
        print("✅ Google's certificate meets expected security standards")

    @pytest.mark.slow 
    @pytest.mark.asyncio
    async def test_error_handling_with_invalid_hostname(self):
        """
        Test error handling when trying to fetch from an invalid hostname
        """
        
        # Try to fetch from a non-existent domain
        fetch_result = await fetch_certificate({
            "hostname": "this-domain-does-not-exist-12345.invalid", 
            "port": 443
        })
        
        assert len(fetch_result) == 1
        assert fetch_result[0].type == "text"
        assert "Failed to fetch certificate" in fetch_result[0].text
        
        # Should contain some kind of error message
        error_text = fetch_result[0].text.lower()
        assert any(term in error_text for term in [
            "name or service not known",
            "nodename nor servname provided", 
            "getaddrinfo failed",
            "connection", 
            "timeout",
            "resolve"
        ]), f"Should contain a network error message, got: {fetch_result[0].text}"
        
        print("✅ Error handling works correctly for invalid hostnames")