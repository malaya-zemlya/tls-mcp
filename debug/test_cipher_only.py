#!/usr/bin/env python3
"""
Test only the cipher analysis part
"""

import asyncio
from tls_mcp_server.main import _analyze_cipher_suites

async def test_cipher_only():
    print("🔐 Testing Cipher Analysis Only")
    print("=" * 40)
    
    print("\nTesting with google.com...")
    result = await _analyze_cipher_suites("google.com", 443, "quick")
    print(result)

if __name__ == "__main__":
    asyncio.run(test_cipher_only())