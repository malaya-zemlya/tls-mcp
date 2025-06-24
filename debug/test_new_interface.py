#!/usr/bin/env python3
"""
Demo of the new unified fetch_certificate interface
"""

import asyncio
from tls_mcp_server.main import fetch_certificate

async def demo_new_interface():
    print("🚀 TLS MCP Server v0.2.0 - New Unified Interface Demo")
    print("=" * 60)
    
    # Test 1: Quick analysis (default)
    print("\n1️⃣ Quick Analysis (Default)")
    print("Command: fetch_certificate({'hostname': 'google.com'})")
    result = await fetch_certificate({"hostname": "google.com"})
    print("\n" + result[0].text[:400] + "..." if len(result[0].text) > 400 else result[0].text)
    
    # Test 2: No analysis, just get PEM
    print("\n2️⃣ No Analysis - Just PEM")
    print("Command: fetch_certificate({'hostname': 'github.com', 'analyze': 'none', 'include_pem': True})")
    result = await fetch_certificate({
        "hostname": "github.com", 
        "analyze": "none",
        "include_pem": True
    })
    print("\n" + result[0].text[:300] + "..." if len(result[0].text) > 300 else result[0].text)
    
    # Test 3: Full analysis with zlint
    print("\n3️⃣ Full Analysis + Compliance Check")
    print("Command: fetch_certificate({'hostname': 'github.com', 'analyze': 'detailed', 'lint': True})")
    result = await fetch_certificate({
        "hostname": "github.com", 
        "analyze": "detailed",
        "lint": True
    })
    print("\n" + result[0].text[:500] + "..." if len(result[0].text) > 500 else result[0].text)
    
    print("\n🎉 Demo complete! Key benefits:")
    print("   ✅ No more PEM copying between tools")
    print("   ✅ Flexible options for any use case")
    print("   ✅ OpenSSL integration when available")
    print("   ✅ Smart defaults that just work")

if __name__ == "__main__":
    asyncio.run(demo_new_interface())