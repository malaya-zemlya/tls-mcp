"""
Unit tests for cipher analysis functionality
"""

import pytest
import subprocess
from unittest.mock import patch, MagicMock

from tls_mcp_server.main import (
    _categorize_cipher_security,
    _check_tls_versions,
    _test_single_cipher,
    _test_single_cipher_tls13,
    _generate_security_assessment
)


class TestCipherAnalysis:
    """Test class for cipher analysis functionality"""

    def test_categorize_cipher_security(self):
        """Test cipher security categorization"""
        # Test secure ciphers
        assert _categorize_cipher_security("TLS_AES_256_GCM_SHA384") == "secure"
        assert _categorize_cipher_security("ECDHE-RSA-AES256-GCM-SHA384") == "secure"
        assert _categorize_cipher_security("ECDHE-ECDSA-CHACHA20-POLY1305") == "secure"
        
        # Test good ciphers
        assert _categorize_cipher_security("ECDHE-RSA-AES256-SHA384") == "good"
        assert _categorize_cipher_security("DHE-RSA-AES256-GCM-SHA384") == "good"
        
        # Test weak ciphers
        assert _categorize_cipher_security("AES256-GCM-SHA384") == "weak"
        assert _categorize_cipher_security("AES128-SHA") == "weak"
        assert _categorize_cipher_security("ECDHE-RSA-AES256-SHA") == "weak"
        
        # Test deprecated ciphers
        assert _categorize_cipher_security("RC4-SHA") == "deprecated"
        assert _categorize_cipher_security("DES-CBC3-SHA") == "deprecated"
        assert _categorize_cipher_security("NULL-MD5") == "deprecated"
        
        # Test heuristic categorization
        assert _categorize_cipher_security("UNKNOWN-ECDHE-AES256-GCM") == "secure"
        assert _categorize_cipher_security("UNKNOWN-ECDHE-AES128") == "good"
        assert _categorize_cipher_security("UNKNOWN-AES256") == "weak"
        assert _categorize_cipher_security("UNKNOWN-RC4-SOMETHING") == "deprecated"

    @pytest.mark.asyncio
    async def test_check_tls_versions_success(self):
        """Test TLS version checking with successful connections"""
        with patch('subprocess.run') as mock_run:
            # Mock successful TLS 1.3 and 1.2, failed 1.1 and 1.0
            def mock_subprocess_run(cmd, **kwargs):
                result = MagicMock()
                if '-tls1_3' in cmd:
                    result.returncode = 0
                    result.stdout = ""
                    result.stderr = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3"
                elif '-tls1_2' in cmd:
                    result.returncode = 0
                    result.stdout = ""
                    result.stderr = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.2"
                else:
                    result.returncode = 1
                    result.stderr = "no protocols available"
                    result.stdout = ""
                return result
            
            mock_run.side_effect = mock_subprocess_run
            
            result = await _check_tls_versions("example.com", 443)
            
            expected = {"1.0": False, "1.1": False, "1.2": True, "1.3": True}
            assert result == expected
            assert mock_run.call_count == 4

    @pytest.mark.asyncio
    async def test_check_tls_versions_timeout(self):
        """Test TLS version checking with timeout"""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("openssl", 10)
            
            result = await _check_tls_versions("example.com", 443)
            
            expected = {"1.0": False, "1.1": False, "1.2": False, "1.3": False}
            assert result == expected

    @pytest.mark.asyncio
    async def test_test_single_cipher_success(self):
        """Test single cipher testing with successful connection"""
        with patch('subprocess.run') as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = ""
            result_mock.stderr = "CONNECTION ESTABLISHED\nCiphersuite: ECDHE-RSA-AES256-GCM-SHA384"
            mock_run.return_value = result_mock
            
            result = await _test_single_cipher("example.com", 443, "ECDHE-RSA-AES256-GCM-SHA384", "1.2")
            
            assert result is True
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "openssl" in call_args
            assert "s_client" in call_args
            assert "-tls1_2" in call_args
            assert "-cipher" in call_args
            assert "ECDHE-RSA-AES256-GCM-SHA384" in call_args

    @pytest.mark.asyncio
    async def test_test_single_cipher_failure(self):
        """Test single cipher testing with failed connection"""
        with patch('subprocess.run') as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 1
            result_mock.stdout = ""
            result_mock.stderr = "no cipher match"
            mock_run.return_value = result_mock
            
            result = await _test_single_cipher("example.com", 443, "WEAK-CIPHER", "1.2")
            
            assert result is False

    @pytest.mark.asyncio
    async def test_test_single_cipher_tls13_success(self):
        """Test TLS 1.3 cipher testing"""
        with patch('subprocess.run') as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = ""
            result_mock.stderr = "CONNECTION ESTABLISHED\nCiphersuite: TLS_AES_256_GCM_SHA384"
            mock_run.return_value = result_mock
            
            result = await _test_single_cipher_tls13("example.com", 443, "TLS_AES_256_GCM_SHA384")
            
            assert result is True
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "openssl" in call_args
            assert "s_client" in call_args
            assert "-tls1_3" in call_args
            assert "-ciphersuites" in call_args
            assert "TLS_AES_256_GCM_SHA384" in call_args

    @pytest.mark.asyncio
    async def test_generate_security_assessment(self):
        """Test security assessment generation"""
        # Test data with mixed cipher security levels
        supported_ciphers = [
            {'cipher': 'TLS_AES_256_GCM_SHA384', 'tls_version': '1.3'},
            {'cipher': 'ECDHE-RSA-AES256-GCM-SHA384', 'tls_version': '1.2'},
            {'cipher': 'ECDHE-RSA-AES128-SHA256', 'tls_version': '1.2'},
            {'cipher': 'AES256-SHA', 'tls_version': '1.2'},
            {'cipher': 'DES-CBC3-SHA', 'tls_version': '1.2'},
        ]
        
        result = await _generate_security_assessment(supported_ciphers)
        
        # Check that assessment includes expected elements
        assert "Security Assessment:" in result
        assert "Perfect Forward Secrecy: Yes" in result
        assert "TLS 1.3 Support: Yes" in result
        assert "Strong ciphers: 2" in result
        assert "Deprecated ciphers: 1" in result
        assert "Security Grade:" in result
        
        # With deprecated ciphers, grade should be F
        assert "Security Grade: F" in result

    @pytest.mark.asyncio  
    async def test_generate_security_assessment_a_grade(self):
        """Test security assessment with A grade"""
        # Test data with only secure ciphers
        supported_ciphers = [
            {'cipher': 'TLS_AES_256_GCM_SHA384', 'tls_version': '1.3'},
            {'cipher': 'TLS_CHACHA20_POLY1305_SHA256', 'tls_version': '1.3'},
            {'cipher': 'ECDHE-RSA-AES256-GCM-SHA384', 'tls_version': '1.2'},
        ]
        
        result = await _generate_security_assessment(supported_ciphers)
        
        assert "Perfect Forward Secrecy: Yes" in result
        assert "TLS 1.3 Support: Yes" in result
        assert "Strong ciphers: 3" in result
        assert "No weak ciphers detected" in result
        assert "Security Grade: A+" in result

    @pytest.mark.asyncio
    async def test_cipher_timeout_handling(self):
        """Test timeout handling in cipher testing"""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("openssl", 8)
            
            result = await _test_single_cipher("example.com", 443, "TEST-CIPHER", "1.2")
            assert result is False
            
            result = await _test_single_cipher_tls13("example.com", 443, "TLS_TEST_CIPHER")
            assert result is False

    def test_cipher_categorization_edge_cases(self):
        """Test edge cases in cipher categorization"""
        # Test empty cipher name
        assert _categorize_cipher_security("") == "weak"
        
        # Test cipher with mixed case
        assert _categorize_cipher_security("ecdhe-rsa-aes256-gcm-sha384") == "secure"
        assert _categorize_cipher_security("ECDHE-RSA-AES256-GCM-SHA384") == "secure"
        
        # Test unknown cipher patterns
        assert _categorize_cipher_security("FUTURE-QUANTUM-CIPHER-2030") == "weak"
        assert _categorize_cipher_security("DHE-SOMETHING-NEW") == "good"