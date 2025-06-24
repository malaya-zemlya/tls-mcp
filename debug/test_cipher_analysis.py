#!/usr/bin/env python3
"""
Test the new cipher analysis functionality
"""

import asyncio
from tls_mcp_server.main import fetch_certificate

async def test_cipher_analysis():
    print("🔐 Testing Cipher Analysis Functionality")
    print("=" * 50)
    
    # Test 1: Quick cipher analysis
    print("\n1️⃣ Quick Cipher Analysis")
    print("Command: fetch_certificate({'hostname': 'google.com', 'analyze_ciphers': True})")
    
    result = await fetch_certificate({
        "hostname": "google.com",
        "analyze_ciphers": True,
        "cipher_scan_type": "quick"
    })
    
    print("\n" + result[0].text[:1000] + "..." if len(result[0].text) > 1000 else result[0].text)
    
    # Test 2: Certificate analysis + cipher analysis
    print("\n" + "="*50)
    print("\n2️⃣ Combined Certificate + Cipher Analysis") 
    print("Command: fetch_certificate({'hostname': 'github.com', 'analyze': 'quick', 'analyze_ciphers': True})")
    
    result = await fetch_certificate({
        "hostname": "github.com",
        "analyze": "quick", 
        "analyze_ciphers": True,
        "cipher_scan_type": "quick"
    })
    
    print("\n" + result[0].text[:1200] + "..." if len(result[0].text) > 1200 else result[0].text)

if __name__ == "__main__":
    asyncio.run(test_cipher_analysis())