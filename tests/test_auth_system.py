

import pytest
import tempfile
import pytest
import logging
from pathlib import Path

# Enable debug logging to see credential attempts
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s | %(name)s:%(lineno)d | %(message)s')

from binsync.core.git_backend import GitBackend

def test_auth_system():
    """Test the authentication system without actually connecting to remote"""
    
    print("=== Testing Authentication System ===")
    
    # Test 1: Check credential callback creation
    print("\n--- Test 1: Credential Callback Creation ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            backend = GitBackend("testuser", tmpdir, "testhash", init_repo=True)
            
            # Test creating credentials callback
            callback = backend._create_credentials_callback()
            print("✅ Successfully created credentials callback")
            
            # Test calling the callback (this will fail but should not crash)
            try:
                result = callback("https://github.com/test/repo.git", "git", 0)
                print(f"Callback result: {result}")
            except Exception as e:
                print(f"Callback failed as expected: {e}")
            
            backend.shutdown()
            
        except Exception as e:
            print(f"❌ Failed to create backend: {e}")
            import traceback
            traceback.print_exc()
    
    # Test 2: SSH key detection
    print("\n--- Test 2: SSH Key Detection ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            backend = GitBackend("testuser", tmpdir, "testhash", init_repo=True)
            
            ssh_keys = backend._get_ssh_key_paths()
            print(f"Found {len(ssh_keys)} potential SSH key locations:")
            for private_key, public_key in ssh_keys:
                exists = "✅" if private_key.exists() else "❌"
                print(f"  {exists} {private_key}")
            
            backend.shutdown()
            
        except Exception as e:
            print(f"❌ Failed SSH key detection: {e}")
    
    # Test 3: Credential helper check
    print("\n--- Test 3: Credential Helper Check ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            backend = GitBackend("testuser", tmpdir, "testhash", init_repo=True)
            
            username, password = backend._get_stored_credentials("https://github.com/test/repo.git")
            if username and password:
                print(f"✅ Found stored credentials for user: {username}")
            else:
                print("ℹ️ No stored credentials found (this is normal)")
            
            backend.shutdown()
            
        except Exception as e:
            print(f"❌ Failed credential helper check: {e}")
    
    # Test 4: Authentication status
    print("\n--- Test 4: Authentication Status ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            backend = GitBackend("testuser", tmpdir, "testhash", init_repo=True)
            
            auth_status = backend.get_auth_status()
            print("Authentication Status:")
            print(f"  SSH keys found: {len(auth_status['ssh_keys_found'])}")
            print(f"  SSH agent running: {auth_status['ssh_agent_running']}")
            print(f"  Git credential helper: {auth_status['git_credential_helper'] or 'None'}")
            
            if auth_status['recommendations']:
                print("  Recommendations:")
                for rec in auth_status['recommendations'][:3]:  # Show first 3
                    print(f"    • {rec}")
            
            backend.shutdown()
            
        except Exception as e:
            print(f"❌ Failed auth status check: {e}")
    
    print("\n✅ Authentication system test completed!")

if __name__ == "__main__":
    pytest.main([__file__])
    
# Legacy main:
    test_auth_system()