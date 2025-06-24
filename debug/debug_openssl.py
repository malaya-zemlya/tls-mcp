#!/usr/bin/env python3
"""
Debug OpenSSL s_client output to see what we're getting
"""

import subprocess

def test_openssl_debug():
    print("🔍 Debugging OpenSSL s_client output")
    print("=" * 50)
    
    hostname = "google.com"
    port = 443
    
    for version_name, openssl_flag in [("1.3", "tls1_3"), ("1.2", "tls1_2"), ("1.1", "tls1_1"), ("1.0", "tls1")]:
        print(f"\n🧪 Testing TLS {version_name} ({openssl_flag})")
        print("-" * 30)
        
        cmd = [
            'openssl', 's_client', 
            '-connect', f'{hostname}:{port}',
            f'-{openssl_flag}',
            '-brief'
        ]
        
        print(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10,
                input='\n'
            )
            
            print(f"Return code: {result.returncode}")
            print(f"STDOUT length: {len(result.stdout)}")
            print(f"STDERR length: {len(result.stderr)}")
            
            print("\nSTDOUT:")
            print(repr(result.stdout[:200]))
            
            print("\nSTDERR:")
            print(repr(result.stderr[:200]))
            
            # Check conditions
            has_connection = 'CONNECTION ESTABLISHED' in result.stdout
            has_protocol = 'Protocol version:' in result.stdout
            has_error = 'no protocols available' in result.stderr
            has_other_error = 'error:' in result.stderr.lower()
            
            print(f"\nCondition checks:")
            print(f"  Return code == 0: {result.returncode == 0}")
            print(f"  Has 'CONNECTION ESTABLISHED': {has_connection}")
            print(f"  Has 'Protocol version:': {has_protocol}")
            print(f"  Has 'no protocols available': {has_error}")
            print(f"  Has other error: {has_other_error}")
            
            success = (result.returncode == 0 and 
                      (has_connection or has_protocol) and
                      not has_error and not has_other_error)
            
            print(f"  Overall success: {success}")
            
        except Exception as e:
            print(f"Exception: {e}")

if __name__ == "__main__":
    test_openssl_debug()