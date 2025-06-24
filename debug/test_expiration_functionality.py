#!/usr/bin/env python3
"""
Debug script to test certificate expiration checking functionality
"""

import asyncio
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tls_mcp_server.main import fetch_certificate


async def test_expiration_check():
    """Test the certificate expiration checking with various domains"""
    
    print("🧪 Testing Certificate Expiration Checking Functionality")
    print("=" * 60)
    
    # Test domains with different certificate characteristics
    test_cases = [
        {"hostname": "google.com", "description": "Google (long-lived cert)"},
        {"hostname": "github.com", "description": "GitHub (standard cert)"},
        {"hostname": "badssl.com", "description": "BadSSL test site"},
        {"hostname": "expired.badssl.com", "description": "Expired certificate test"},
    ]
    
    for case in test_cases:
        print(f"\n🔍 Testing: {case['description']}")
        print("-" * 40)
        
        try:
            result = await fetch_certificate({
                'hostname': case['hostname'], 
                'analyze': 'quick'
            })
            
            # Extract just the expiration line from the output
            output_lines = result[0].text.split('\n')
            expiration_line = None
            for line in output_lines:
                if any(indicator in line for indicator in ['expires in', 'expired', 'become valid']):
                    expiration_line = line.strip()
                    break
            
            if expiration_line:
                print(f"✅ Expiration Status: {expiration_line}")
            else:
                print("❌ No expiration status found in output")
                
        except Exception as e:
            print(f"❌ Error testing {case['hostname']}: {e}")
    
    print(f"\n🎯 Testing Complete!")


async def test_duration_formatting():
    """Test the duration formatting function directly"""
    from tls_mcp_server.main import _format_duration_human_friendly
    
    print("\n🧪 Testing Duration Formatting")
    print("=" * 40)
    
    test_durations = [
        (30, "30 seconds"),
        (90, "1 minute"), 
        (3600, "1 hour"),
        (7200, "2 hours"),
        (86400, "1 day"),
        (172800, "2 days"),
        (2592000, "30 days"),
        (31536000, "1 year"),
    ]
    
    for seconds, expected_format in test_durations:
        actual = _format_duration_human_friendly(seconds)
        status = "✅" if actual == expected_format else "❌"
        print(f"{status} {seconds}s -> {actual} (expected: {expected_format})")


if __name__ == "__main__":
    asyncio.run(test_expiration_check())
    asyncio.run(test_duration_formatting())