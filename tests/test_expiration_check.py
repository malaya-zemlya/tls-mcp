"""
Unit tests for certificate expiration checking functionality
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from tls_mcp_server.main import (
    _format_duration_human_friendly,
    _check_certificate_validity
)


class TestExpirationCheck:
    """Test class for certificate expiration functionality"""

    def test_format_duration_human_friendly(self):
        """Test human-friendly duration formatting"""
        # Test seconds
        assert _format_duration_human_friendly(30) == "30 seconds"
        assert _format_duration_human_friendly(1) == "1 second"
        
        # Test minutes  
        assert _format_duration_human_friendly(90) == "1 minute"
        assert _format_duration_human_friendly(180) == "3 minutes"
        assert _format_duration_human_friendly(3660) == "1 hour"  # 61 minutes = 1 hour (rounded to largest unit)
        
        # Test hours
        assert _format_duration_human_friendly(3600) == "1 hour"
        assert _format_duration_human_friendly(7200) == "2 hours"
        assert _format_duration_human_friendly(90000) == "1 day"  # 25 hours = 1 day (rounded to largest unit)
        
        # Test days
        assert _format_duration_human_friendly(86400) == "1 day"
        assert _format_duration_human_friendly(172800) == "2 days"
        assert _format_duration_human_friendly(2592000) == "30 days"
        
        # Test years
        assert _format_duration_human_friendly(31536000) == "1 year"
        assert _format_duration_human_friendly(63072000) == "2 years"

    def test_format_duration_negative(self):
        """Test duration formatting handles negative values"""
        assert _format_duration_human_friendly(-3600) == "1 hour"
        assert _format_duration_human_friendly(-86400) == "1 day"

    @patch('tls_mcp_server.main.datetime')
    def test_check_certificate_validity_future(self, mock_datetime):
        """Test certificate that will be valid in the future"""
        # Mock current time
        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        
        # Certificate valid from tomorrow
        not_before = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
        not_after = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        result = _check_certificate_validity(not_before, not_after)
        assert "will become valid in 1 day" in result
        assert "⏳" in result

    @patch('tls_mcp_server.main.datetime')
    def test_check_certificate_validity_expired(self, mock_datetime):
        """Test expired certificate"""
        # Mock current time
        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        
        # Certificate expired yesterday
        not_before = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        not_after = datetime(2023, 12, 31, 12, 0, 0, tzinfo=timezone.utc)
        
        result = _check_certificate_validity(not_before, not_after)
        assert "has expired 1 day ago" in result
        assert "🔴" in result

    @patch('tls_mcp_server.main.datetime')
    def test_check_certificate_validity_expiring_soon(self, mock_datetime):
        """Test certificate expiring within 7 days"""
        # Mock current time
        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        
        # Certificate expires in 3 days
        not_before = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        not_after = datetime(2024, 1, 4, 12, 0, 0, tzinfo=timezone.utc)
        
        result = _check_certificate_validity(not_before, not_after)
        assert "expires in 3 days" in result
        assert "expiring soon!" in result
        assert "⚠️" in result

    @patch('tls_mcp_server.main.datetime')
    def test_check_certificate_validity_expiring_warning(self, mock_datetime):
        """Test certificate expiring within 30 days but not soon"""
        # Mock current time
        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        
        # Certificate expires in 15 days
        not_before = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        not_after = datetime(2024, 1, 16, 12, 0, 0, tzinfo=timezone.utc)
        
        result = _check_certificate_validity(not_before, not_after)
        assert "expires in 15 days" in result
        assert "🟡" in result
        assert "expiring soon!" not in result

    @patch('tls_mcp_server.main.datetime')
    def test_check_certificate_validity_valid_long_term(self, mock_datetime):
        """Test certificate valid for a long time"""
        # Mock current time
        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        
        # Certificate expires in 6 months
        not_before = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        not_after = datetime(2024, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        result = _check_certificate_validity(not_before, not_after)
        assert "expires in 182 days" in result
        assert "✅" in result

    @patch('tls_mcp_server.main.datetime')
    def test_check_certificate_validity_timezone_handling(self, mock_datetime):
        """Test that timezone handling works correctly"""
        # Mock current time in UTC
        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        
        # Certificate times should be in UTC
        not_before = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        not_after = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
        
        result = _check_certificate_validity(not_before, not_after)
        assert "expires in 1 day" in result