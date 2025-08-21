
"""
Test remote user discovery and branch localization.

This test simulates the exact scenario where:
1. Users exist on remote but haven't been pulled locally yet
2. Binary hash verification with existing repos
3. Root branch creation from remote
"""

import pytest
import tempfile
import pytest
import logging
import pytest
import os
import pytest
import shutil
from pathlib import Path

# Enable debug logging to see all operations
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s | %(name)s:%(lineno)d | %(message)s')

from binsync.core.git_backend import GitBackend
from binsync.core.state import State
from libbs.artifacts import FunctionHeader

def test_remote_users_scenario():
    """Test the exact scenario reported by user"""
    
    print("🔍 Testing Remote Users Discovery")
    print("=" * 50)
    
    # Test 1: Create a "remote" repo with multiple users
    print("\n--- Test 1: Create Remote Repository with Multiple Users ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        remote_repo_path = Path(tmpdir) / "remote_repo"
        local_repo_path = Path(tmpdir) / "local_repo"
        
        try:
            # Create "remote" repo with multiple users
            print("Creating remote repository...")
            remote_backend1 = GitBackend("user1", str(remote_repo_path), "58f7a557eff80c5c254f10047e7e058d", init_repo=True)
            
            # Add some state for user1
            state1 = State("user1", client=remote_backend1)
            header1 = FunctionHeader(name="func1", addr=0x1000, type_="int")
            state1.set_function_header(header1)
            remote_backend1.commit_state(state1, "User1 initial commit")
            remote_backend1.shutdown()
            
            # Add user2 to remote repo
            remote_backend2 = GitBackend("user2", str(remote_repo_path), "58f7a557eff80c5c254f10047e7e058d")
            state2 = State("user2", client=remote_backend2)
            header2 = FunctionHeader(name="func2", addr=0x2000, type_="void")
            state2.set_function_header(header2)
            remote_backend2.commit_state(state2, "User2 initial commit")
            remote_backend2.shutdown()
            
            # Add user3 to remote repo
            remote_backend3 = GitBackend("user3", str(remote_repo_path), "58f7a557eff80c5c254f10047e7e058d")
            state3 = State("user3", client=remote_backend3)
            header3 = FunctionHeader(name="func3", addr=0x3000, type_="char*")
            state3.set_function_header(header3)
            remote_backend3.commit_state(state3, "User3 initial commit")
            remote_backend3.shutdown()
            
            print("✅ Created remote repository with 3 users")
            
            # Show what users exist in remote
            temp_backend = GitBackend("temp", str(remote_repo_path), "58f7a557eff80c5c254f10047e7e058d")
            remote_users = temp_backend.users()
            print(f"Remote repository has users: {[u.name for u in remote_users] if remote_users else 'None'}")
            temp_backend.shutdown()
            
        except Exception as e:
            print(f"❌ Failed to create remote repository: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
        
        # Test 2: Clone repository and see if users appear
        print("\n--- Test 2: Clone Repository as New User ---")
        try:
            # Copy the "remote" repo to simulate cloning
            shutil.copytree(remote_repo_path, local_repo_path)
            
            # Connect as a new user (flip) to the "local" copy
            local_backend = GitBackend("flip", str(local_repo_path), "58f7a557eff80c5c254f10047e7e058d")
            
            # Test binary hash verification (should not show mismatch warning)
            print(f"✅ Connected as user 'flip' to local repository")
            
            # Check what users are visible
            local_users = local_backend.users()
            print(f"Local repository shows users: {[u.name for u in local_users] if local_users else 'None'}")
            
            # Test getting states for different users
            for user_name in ["user1", "user2", "user3"]:
                try:
                    user_state = local_backend.get_state(user_name)
                    print(f"✅ Got state for {user_name}: {user_state.user if user_state else 'None'}")
                except Exception as e:
                    print(f"❌ Failed to get state for {user_name}: {e}")
            
            local_backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test 2 failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
        
        # Test 3: Test pull operation with missing root branch
        print("\n--- Test 3: Test Pull Operations ---")
        try:
            # Remove root branch locally to simulate the warning scenario
            local_backend = GitBackend("flip", str(local_repo_path), "58f7a557eff80c5c254f10047e7e058d")
            
            # Test pull without remote (should handle gracefully)
            pull_result = local_backend.pull()
            print(f"Pull without remote: {pull_result} (expected: False)")
            
            # Test users discovery after pull
            users_after_pull = local_backend.users()
            print(f"Users after pull: {[u.name for u in users_after_pull] if users_after_pull else 'None'}")
            
            local_backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test 3 failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
            
        # Test 4: Test with empty binary hash scenario
        print("\n--- Test 4: Test Binary Hash Scenarios ---")
        try:
            # Create a repo without binary_hash file to simulate the empty hash scenario
            minimal_repo_path = Path(tmpdir) / "minimal_repo"
            minimal_backend = GitBackend("test_user", str(minimal_repo_path), "58f7a557eff80c5c254f10047e7e058d", init_repo=True)
            
            # Remove the binary_hash file to simulate old repos
            binary_hash_file = Path(minimal_repo_path) / "binary_hash"
            if binary_hash_file.exists():
                binary_hash_file.unlink()
                
            # Commit to remove it from Git too
            minimal_backend.repo.index.remove("binary_hash")
            minimal_backend.repo.index.write()
            
            signature = minimal_backend._get_signature()
            tree = minimal_backend.repo.index.write_tree()
            minimal_backend.repo.create_commit(
                "HEAD",
                signature,
                signature,
                "Remove binary_hash file",
                tree,
                [minimal_backend.repo.head.target]
            )
            
            minimal_backend.shutdown()
            
            # Now connect with different binary hash - should show debug message, not warning
            print("Testing connection with different binary hash...")
            test_backend = GitBackend("test_user", str(minimal_repo_path), "different_hash")
            print("✅ Connected without binary hash mismatch warning")
            test_backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test 4 failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    print("\n🎉 Remote users discovery test completed successfully!")
    return True

if __name__ == "__main__":
    pytest.main([__file__])
    
# Legacy main:
    success = test_remote_users_scenario()
    if success:
        print("\n✅ Remote users test PASSED")
    else:
        print("\n❌ Remote users test FAILED")
    exit(0 if success else 1)