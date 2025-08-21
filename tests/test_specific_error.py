

import pytest
import tempfile
import logging
import sys
import os
import shutil
from pathlib import Path

# Set up logging to capture all debug info
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s | %(name)s | %(message)s')

from binsync.core.client import Client

def test_edge_cases():
    """Test specific edge cases that might cause 'NoneType' object has no attribute 'target'"""
    
    print("=== Testing Edge Cases ===")
    
    # Test 1: Try to connect to a corrupted repository
    print("\n--- Test 1: Corrupted repository ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Create a BinSync repo first
            client1 = Client("user1", tmpdir, "testhash", init_repo=True)
            state1 = client1.get_state()
            client1.shutdown()
            
            # Now corrupt the git repository by removing some refs
            refs_dir = Path(tmpdir) / ".git" / "refs" / "heads"
            for ref_file in refs_dir.glob("*"):
                if "binsync" in ref_file.name:
                    print(f"Removing ref file: {ref_file}")
                    ref_file.unlink()
            
            # Try to connect to the corrupted repo
            client2 = Client("user2", tmpdir, "testhash")
            print("✅ Connected to corrupted repo")
            state2 = client2.get_state()
            print(f"✅ Got state from corrupted repo: {state2}")
            client2.shutdown()
            
        except Exception as e:
            print(f"❌ Failed with corrupted repo: {e}")
            import traceback
            traceback.print_exc()
    
    # Test 2: Repository with no HEAD
    print("\n--- Test 2: Repository with no HEAD ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Create a minimal git repo without commits
            import subprocess
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True, check=True)
            
            # Try to connect (this should fail gracefully)
            client = Client("testuser", tmpdir, "testhash")
            print("❌ Should have failed with no HEAD")
            client.shutdown()
            
        except Exception as e:
            print(f"✅ Correctly failed with no HEAD: {e}")
    
    # Test 3: Repository with missing root branch
    print("\n--- Test 3: Repository missing root branch ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Create a git repo with commits but no binsync root
            import subprocess
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmpdir, capture_output=True, check=True)
            Path(tmpdir, "test.txt").write_text("test")
            subprocess.run(["git", "add", "test.txt"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "test"], cwd=tmpdir, capture_output=True, check=True)
            
            # Try to connect
            client = Client("testuser", tmpdir, "testhash")
            print("❌ Should have failed with missing root branch")
            client.shutdown()
            
        except Exception as e:
            print(f"✅ Correctly failed with missing root branch: {e}")
    
    # Test 4: Empty repository directory
    print("\n--- Test 4: Empty repository directory ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            client = Client("testuser", tmpdir, "testhash", init_repo=True)
            print("✅ Created repo in empty directory")
            state = client.get_state()
            print(f"✅ Got state: {state}")
            client.shutdown()
            
        except Exception as e:
            print(f"❌ Failed with empty directory: {e}")
            import traceback
            traceback.print_exc()
    
    # Test 5: Test with various binary hash values
    print("\n--- Test 5: Different binary hash values ---")
    test_hashes = ["", "short", "a" * 64, b"bytes_hash", None]
    
    for i, test_hash in enumerate(test_hashes):
        print(f"\nTesting hash {i}: {test_hash}")
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                if test_hash is None:
                    continue  # Skip None hash as it would fail validation
                    
                client = Client("testuser", tmpdir, str(test_hash), init_repo=True)
                print(f"✅ Created repo with hash: {test_hash}")
                client.shutdown()
                
            except Exception as e:
                print(f"❌ Failed with hash {test_hash}: {e}")

if __name__ == "__main__":
    pytest.main([__file__])
    
# Legacy main:
    test_edge_cases()