#!/usr/bin/env python3
"""
TLS MCP Server - Main entry point

This file creates an MCP server that provides TLS certificate analysis tools.
MCP (Model Context Protocol) allows Claude to use these tools through a standardized interface.
"""

import asyncio
import json
import logging
import ssl
import socket
import subprocess
from typing import Dict, Any, Optional
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Import cryptography for certificate parsing
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the MCP server instance
server = Server("tls-mcp-server")

@server.list_tools()
async def list_tools() -> list[Tool]:
    """
    List all available tools that Claude can use.
    
    This function tells Claude what tools are available and how to use them.
    Each tool has a name, description, and input schema.
    """
    return [
        Tool(
            name="fetch_certificate",
            description="Fetch and analyze TLS certificate from a website with flexible output options",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "The hostname to fetch certificate from (e.g., 'google.com')"
                    },
                    "port": {
                        "type": "integer",
                        "description": "The port to connect to (default: 443)",
                        "default": 443
                    },
                    "include_pem": {
                        "type": "boolean",
                        "description": "Include the raw PEM certificate in output (default: false)",
                        "default": False
                    },
                    "analyze": {
                        "type": "string",
                        "description": "Level of analysis to perform: 'none', 'quick', or 'detailed' (default: 'quick')",
                        "enum": ["none", "quick", "detailed"],
                        "default": "quick"
                    },
                    "lint": {
                        "type": "boolean",
                        "description": "Run zlint compliance checking (default: false)",
                        "default": False
                    },
                    "use_openssl": {
                        "type": "boolean",
                        "description": "Use OpenSSL for analysis when available (default: true)",
                        "default": True
                    },
                    "analyze_ciphers": {
                        "type": "boolean",
                        "description": "Analyze supported cipher suites and TLS versions (default: false)",
                        "default": False
                    },
                    "cipher_scan_type": {
                        "type": "string",
                        "description": "Type of cipher scan: 'quick' or 'full' (default: 'quick')",
                        "enum": ["quick", "full"],
                        "default": "quick"
                    }
                },
                "required": ["hostname"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> list[TextContent]:
    """
    Handle tool calls from Claude.
    
    This function receives the tool name and arguments, then calls the appropriate
    function to handle the request.
    """
    try:
        if name == "fetch_certificate":
            return await fetch_certificate(arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        logger.error(f"Error calling tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def fetch_certificate(arguments: Dict[str, Any]) -> list[TextContent]:
    """
    Fetch and analyze TLS certificate from a website with flexible options.
    
    This function can:
    1. Fetch the certificate from any website
    2. Optionally include the raw PEM in output
    3. Perform quick or detailed analysis
    4. Run zlint compliance checking
    5. Use OpenSSL or Python cryptography for analysis
    """
    hostname = arguments["hostname"]
    port = arguments.get("port", 443)
    include_pem = arguments.get("include_pem", False)
    analyze_level = arguments.get("analyze", "quick")
    run_lint = arguments.get("lint", False)
    use_openssl = arguments.get("use_openssl", True)
    analyze_ciphers = arguments.get("analyze_ciphers", False)
    cipher_scan_type = arguments.get("cipher_scan_type", "quick")
    
    logger.info(f"Fetching certificate from {hostname}:{port} (analyze={analyze_level}, lint={run_lint}, ciphers={analyze_ciphers})")
    
    try:
        # Step 1: Fetch the certificate
        cert_pem = await _fetch_raw_certificate(hostname, port)
        
        # Step 2: Build the response
        result = f"📜 Certificate Analysis for {hostname}:{port}\n"
        result += "=" * 60 + "\n\n"
        
        # Step 3: Add analysis based on options
        if analyze_level != "none":
            if use_openssl and await _is_openssl_available():
                analysis = await _analyze_with_openssl(cert_pem, analyze_level)
            else:
                analysis = await _analyze_with_cryptography(cert_pem, analyze_level)
            result += analysis + "\n"
        
        # Step 4: Add cipher analysis if requested
        if analyze_ciphers:
            cipher_results = await _analyze_cipher_suites(hostname, port, cipher_scan_type)
            result += cipher_results + "\n"
        
        # Step 5: Add zlint results if requested
        if run_lint:
            lint_results = await _run_zlint(cert_pem)
            result += lint_results + "\n"
        
        # Step 6: Add raw PEM if requested
        if include_pem:
            result += "\n" + "📋 Raw PEM Certificate:\n"
            result += "-" * 30 + "\n"
            result += cert_pem + "\n"
        
        return [TextContent(type="text", text=result)]
        
    except Exception as e:
        error_msg = f"Failed to fetch certificate from {hostname}:{port}: {str(e)}"
        logger.error(error_msg)
        return [TextContent(type="text", text=error_msg)]

async def _fetch_raw_certificate(hostname: str, port: int) -> str:
    """Helper function to fetch raw certificate from a server."""
    # Create SSL context with verification disabled
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Connect and get certificate
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            return ssl.DER_cert_to_PEM_cert(cert_der)

async def _is_openssl_available() -> bool:
    """Check if OpenSSL command is available."""
    try:
        result = subprocess.run(['openssl', 'version'], 
                              capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

async def _analyze_with_openssl(cert_pem: str, level: str) -> str:
    """Analyze certificate using OpenSSL command."""
    import tempfile
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_file:
            temp_file.write(cert_pem)
            temp_file_path = temp_file.name
        
        # Choose OpenSSL command based on analysis level
        if level == "quick":
            cmd = ['openssl', 'x509', '-in', temp_file_path, '-text', '-noout', '-subject', '-issuer', '-dates']
        else:  # detailed
            cmd = ['openssl', 'x509', '-in', temp_file_path, '-text', '-noout']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        Path(temp_file_path).unlink()
        
        if result.returncode == 0:
            output = "🔧 Analysis (OpenSSL):\n"
            output += "-" * 30 + "\n"
            output += result.stdout
            return output
        else:
            # Fall back to cryptography if OpenSSL fails
            return await _analyze_with_cryptography(cert_pem, level)
            
    except Exception:
        # Fall back to cryptography if OpenSSL fails
        return await _analyze_with_cryptography(cert_pem, level)

async def _analyze_with_cryptography(cert_pem: str, level: str) -> str:
    """Analyze certificate using Python cryptography library."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        if level == "quick":
            # Quick analysis - just the essentials
            output = "🐍 Quick Analysis (cryptography):\n"
            output += "-" * 30 + "\n"
            output += f"Subject: {cert.subject.rfc4514_string()}\n"
            output += f"Issuer: {cert.issuer.rfc4514_string()}\n"
            output += f"Valid From: {cert.not_valid_before_utc.isoformat()}\n"
            output += f"Valid Until: {cert.not_valid_after_utc.isoformat()}\n"
            output += f"Serial Number: {cert.serial_number}\n"
            
            # Add SANs if present
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = [name.value for name in san_ext.value]
                output += f"Subject Alternative Names: {', '.join(sans[:5])}"
                if len(sans) > 5:
                    output += f" (and {len(sans)-5} more)"
                output += "\n"
            except x509.ExtensionNotFound:
                pass
                
        else:  # detailed
            # Detailed analysis
            output = "🐍 Detailed Analysis (cryptography):\n"
            output += "-" * 30 + "\n"
            output += f"Subject: {cert.subject.rfc4514_string()}\n"
            output += f"Issuer: {cert.issuer.rfc4514_string()}\n"
            output += f"Serial Number: {cert.serial_number}\n"
            output += f"Version: {cert.version.name}\n"
            output += f"Valid From: {cert.not_valid_before_utc.isoformat()}\n"
            output += f"Valid Until: {cert.not_valid_after_utc.isoformat()}\n"
            output += f"Signature Algorithm: {cert.signature_algorithm_oid._name}\n"
            
            # Public key info
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                output += f"Public Key Size: {public_key.key_size} bits\n"
            output += f"Public Key Type: {type(public_key).__name__}\n"
            
            # Extensions
            output += f"\nExtensions ({len(cert.extensions)}):\n"
            for ext in cert.extensions:
                output += f"  - {ext.oid._name}: {'Critical' if ext.critical else 'Non-critical'}\n"
                
        return output
        
    except Exception as e:
        return f"❌ Analysis failed: {str(e)}\n"

async def _run_zlint(cert_pem: str) -> str:
    """Run zlint on the certificate."""
    import tempfile
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_file:
            temp_file.write(cert_pem)
            temp_file_path = temp_file.name
        
        result = subprocess.run(
            ['zlint', '-pretty', temp_file_path],
            capture_output=True, text=True, timeout=30
        )
        
        Path(temp_file_path).unlink()
        
        output = "🧪 Compliance Check (zlint):\n"
        output += "-" * 30 + "\n"
        
        if result.returncode == 0:
            output += "✅ No major compliance issues found\n"
        else:
            output += f"⚠️  Issues found (exit code: {result.returncode})\n"
        
        if result.stdout.strip():
            output += "\nResults:\n" + result.stdout
        if result.stderr.strip():
            output += "\nWarnings:\n" + result.stderr
            
        return output
        
    except subprocess.TimeoutExpired:
        return "🧪 Compliance Check (zlint):\n❌ zlint timed out\n"
    except FileNotFoundError:
        return "🧪 Compliance Check (zlint):\n❌ zlint not installed\n"
    except Exception as e:
        return f"🧪 Compliance Check (zlint):\n❌ Error: {str(e)}\n"

# Cipher suite definitions and categorization
CIPHER_CATEGORIES = {
    "secure": [
        # TLS 1.3 ciphers
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256", 
        "TLS_AES_128_GCM_SHA256",
        # TLS 1.2 with Perfect Forward Secrecy
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
    ],
    "good": [
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-ECDSA-AES128-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
    ],
    "weak": [
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256", 
        "AES256-SHA256",
        "AES128-SHA256",
        "AES256-SHA",
        "AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
    ],
    "deprecated": [
        "DES-CBC3-SHA",
        "RC4-SHA",
        "RC4-MD5",
        "DES-CBC-SHA",
        "EXP-RC4-MD5",
        "EXP-DES-CBC-SHA",
        "NULL-SHA",
        "NULL-MD5",
    ]
}

# Common ciphers to test in quick mode
COMMON_CIPHERS_QUICK = [
    # TLS 1.3 ciphers (tested separately)
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    # Modern TLS 1.2 with PFS
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256", 
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    # Older but common TLS 1.2
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    # Non-PFS but still used
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    # Legacy/weak
    "DES-CBC3-SHA",
]

TLS_VERSIONS = {
    "1.0": "tls1",
    "1.1": "tls1_1", 
    "1.2": "tls1_2",
    "1.3": "tls1_3"
}

async def _analyze_cipher_suites(hostname: str, port: int, scan_type: str) -> str:
    """Analyze supported cipher suites using OpenSSL."""
    try:
        output = "🔐 Cipher Suite Analysis:\n"
        output += "-" * 30 + "\n"
        
        # Step 1: Check TLS version support
        tls_support = await _check_tls_versions(hostname, port)
        output += "\nTLS Version Support:\n"
        for version, supported in tls_support.items():
            status = "✅" if supported else "❌"
            output += f"{status} TLS {version}\n"
        
        # Step 2: Test cipher suites
        if scan_type == "quick":
            ciphers_to_test = COMMON_CIPHERS_QUICK
        else:  # full scan - get all available ciphers
            ciphers_to_test = await _get_all_ciphers()
        
        supported_ciphers = await _test_cipher_suites(hostname, port, ciphers_to_test, tls_support)
        
        if supported_ciphers:
            output += f"\nSupported Cipher Suites ({len(supported_ciphers)} found):\n"
            for cipher_info in supported_ciphers:
                cipher = cipher_info['cipher']
                tls_ver = cipher_info['tls_version']
                security_level = _categorize_cipher_security(cipher)
                icon = {"secure": "🟢", "good": "🟡", "weak": "🟠", "deprecated": "🔴"}.get(security_level, "⚪")
                output += f"{icon} {cipher} (TLS {tls_ver}) - {security_level.title()}\n"
            
            # Security assessment
            output += await _generate_security_assessment(supported_ciphers)
        else:
            output += "\n❌ No cipher suites could be tested (connection issues)\n"
        
        return output
        
    except Exception as e:
        return f"🔐 Cipher Suite Analysis:\n❌ Error: {str(e)}\n"

async def _check_tls_versions(hostname: str, port: int) -> dict:
    """Check which TLS versions are supported."""
    results = {}
    
    for version_name, openssl_flag in TLS_VERSIONS.items():
        try:
            # Test TLS version support with a basic connection
            cmd = [
                'openssl', 's_client', 
                '-connect', f'{hostname}:{port}',
                f'-{openssl_flag}',
                '-brief'
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10,
                input='\n'  # Send newline to close connection immediately
            )
            
            # Check if connection succeeded (OpenSSL outputs to stderr with -brief)
            output = result.stdout + result.stderr
            success = (result.returncode == 0 and 
                      'CONNECTION ESTABLISHED' in output and
                      'Protocol version:' in output and
                      'no protocols available' not in output)
            
            results[version_name] = success
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            results[version_name] = False
    
    return results

async def _get_all_ciphers() -> list[str]:
    """Get all available cipher suites from OpenSSL."""
    try:
        # Get TLS 1.2 and below ciphers
        result = subprocess.run(
            ['openssl', 'ciphers', 'ALL'], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        ciphers = []
        if result.returncode == 0:
            # OpenSSL ciphers returns colon-separated list
            ciphers.extend(result.stdout.strip().split(':'))
        
        # Add TLS 1.3 ciphers manually (they're not in the regular cipher list)
        tls13_ciphers = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"]
        ciphers.extend(tls13_ciphers)
        
        return ciphers[:50]  # Limit to 50 for performance
        
    except Exception:
        # Fallback to common ciphers if command fails
        return COMMON_CIPHERS_QUICK

async def _test_cipher_suites(hostname: str, port: int, ciphers: list[str], tls_support: dict) -> list[dict]:
    """Test which cipher suites are supported."""
    supported = []
    
    for cipher in ciphers:
        # Determine which TLS versions to test this cipher with
        if cipher.startswith('TLS_'):
            # TLS 1.3 cipher
            if tls_support.get('1.3', False):
                if await _test_single_cipher_tls13(hostname, port, cipher):
                    supported.append({'cipher': cipher, 'tls_version': '1.3'})
        else:
            # TLS 1.2 and below cipher
            for version in ['1.2', '1.1', '1.0']:
                if tls_support.get(version, False):
                    if await _test_single_cipher(hostname, port, cipher, version):
                        supported.append({'cipher': cipher, 'tls_version': version})
                        break  # Found support, no need to test older versions
    
    return supported

async def _test_single_cipher(hostname: str, port: int, cipher: str, tls_version: str) -> bool:
    """Test if a single cipher suite is supported for TLS 1.2 and below."""
    try:
        openssl_flag = TLS_VERSIONS[tls_version]
        cmd = [
            'openssl', 's_client',
            '-connect', f'{hostname}:{port}',
            f'-{openssl_flag}',
            '-cipher', cipher,
            '-brief'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=8,
            input='\n'
        )
        
        # Check if connection succeeded and the correct cipher was used (check both stdout and stderr)
        output = result.stdout + result.stderr
        return (result.returncode == 0 and 
                'CONNECTION ESTABLISHED' in output and
                f'Ciphersuite: {cipher}' in output)
        
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False

async def _test_single_cipher_tls13(hostname: str, port: int, cipher: str) -> bool:
    """Test if a TLS 1.3 cipher suite is supported."""
    try:
        cmd = [
            'openssl', 's_client',
            '-connect', f'{hostname}:{port}',
            '-tls1_3',
            '-ciphersuites', cipher,
            '-brief'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=8,
            input='\n'
        )
        
        # Check if connection succeeded and the correct cipher was used (check both stdout and stderr)
        output = result.stdout + result.stderr
        return (result.returncode == 0 and 
                'CONNECTION ESTABLISHED' in output and
                f'Ciphersuite: {cipher}' in output)
        
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False

def _categorize_cipher_security(cipher: str) -> str:
    """Categorize a cipher suite by security level."""
    for category, cipher_list in CIPHER_CATEGORIES.items():
        if cipher in cipher_list:
            return category
    
    # Heuristic categorization for unknown ciphers
    cipher_lower = cipher.lower()
    
    # Deprecated/weak patterns
    if any(weak in cipher_lower for weak in ['rc4', 'des', 'md5', 'exp', 'null']):
        return "deprecated"
    
    # Strong patterns (TLS 1.3 or ECDHE with modern encryption)
    if (cipher.startswith('TLS_') or 
        ('ecdhe' in cipher_lower and ('gcm' in cipher_lower or 'chacha20' in cipher_lower))):
        return "secure"
    
    # Good patterns (ECDHE or DHE with decent encryption)
    if 'ecdhe' in cipher_lower or 'dhe' in cipher_lower:
        return "good"
    
    # Weak patterns (no forward secrecy)
    return "weak"

async def _generate_security_assessment(supported_ciphers: list[dict]) -> str:
    """Generate a security assessment based on supported ciphers."""
    assessment = "\nSecurity Assessment:\n"
    
    # Count by security level
    security_counts = {"secure": 0, "good": 0, "weak": 0, "deprecated": 0}
    tls13_count = 0
    
    for cipher_info in supported_ciphers:
        cipher = cipher_info['cipher']
        tls_version = cipher_info['tls_version']
        
        level = _categorize_cipher_security(cipher)
        security_counts[level] += 1
        
        if tls_version == '1.3':
            tls13_count += 1
    
    # Check for Perfect Forward Secrecy
    pfs_ciphers = [c for c in supported_ciphers 
                   if ('ECDHE' in c['cipher'] or 'DHE' in c['cipher'] or 
                       c['cipher'].startswith('TLS_'))]
    has_pfs = len(pfs_ciphers) > 0
    
    # Generate assessment
    assessment += f"✅ Perfect Forward Secrecy: {'Yes' if has_pfs else 'No'}\n"
    assessment += f"✅ TLS 1.3 Support: {'Yes' if tls13_count > 0 else 'No'}\n"
    
    if security_counts["secure"] > 0:
        assessment += f"✅ Strong ciphers: {security_counts['secure']}\n"
    
    if security_counts["deprecated"] > 0:
        assessment += f"🔴 Deprecated ciphers: {security_counts['deprecated']}\n"
    elif security_counts["weak"] > 0:
        assessment += f"🟠 Weak ciphers: {security_counts['weak']}\n"
    else:
        assessment += "✅ No weak ciphers detected\n"
    
    # Overall grade
    if security_counts["deprecated"] > 0:
        grade = "F"
    elif security_counts["weak"] > security_counts["secure"] + security_counts["good"]:
        grade = "D"
    elif not has_pfs:
        grade = "C"
    elif tls13_count > 0 and security_counts["secure"] > 0 and security_counts["weak"] == 0:
        grade = "A+"
    elif security_counts["secure"] > 0 and security_counts["weak"] == 0:
        grade = "A"
    elif security_counts["secure"] > 0:
        grade = "B+"
    else:
        grade = "B"
    
    assessment += f"🎯 Security Grade: {grade}\n"
    
    return assessment

async def main():
    """
    Main entry point for the MCP server.
    
    This function starts the server and handles communication with Claude.
    """
    logger.info("Starting TLS MCP Server")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())