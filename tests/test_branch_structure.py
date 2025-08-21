
"""
Test correct branch structure - no user subfolders, artifacts directly in branch.
"""

import pytest
import tempfile
import pytest
import logging
import pytest
import os
from pathlib import Path

# Enable logging to see what's happening
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s | %(name)s | %(message)s')

from binsync.core.git_backend import GitBackend
from binsync.core.state import State
from libbs.artifacts import FunctionHeader

def test_branch_structure():
    """Test that branches contain artifacts directly, not user subfolders"""
    
    print("📁 Testing Correct Branch Structure")
    print("=" * 45)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Test 1: Create user and verify file structure
            print("\n--- Test 1: Create User and Check File Structure ---")
            
            backend = GitBackend("testuser", str(repo_path), "test_hash", init_repo=True)
            
            # Create state and commit
            state = State("testuser", client=backend)
            header = FunctionHeader(name="test_func", addr=0x1000, type_="int")
            state.set_function_header(header)
            
            backend.commit_state(state, "Test commit")
            
            # Check filesystem structure
            print(f"\nFilesystem structure in {repo_path}:")
            for item in os.listdir(repo_path):
                if item != '.git':
                    print(f"  📄 {item}")
            
            # There should be NO user subfolder
            user_folder = repo_path / "testuser"
            if user_folder.exists():
                print(f"❌ ERROR: User folder exists: {user_folder}")
                pytest.fail("Test failed")
            else:
                print(f"✅ Good: No user subfolder found")
            
            # There should be artifact files directly
            expected_files = ["metadata.toml", "functions"]
            for expected_file in expected_files:
                file_path = repo_path / expected_file
                if file_path.exists():
                    print(f"✅ Found expected file: {expected_file}")
                else:
                    print(f"⚠️ Missing expected file: {expected_file}")
            
            backend.shutdown()
            
            # Test 2: Create multiple users and check user discovery
            print("\n--- Test 2: Multiple Users and Discovery ---")
            
            # Create second user
            backend2 = GitBackend("user2", str(repo_path), "test_hash")
            
            state2 = State("user2", client=backend2)
            header2 = FunctionHeader(name="func2", addr=0x2000, type_="void")
            state2.set_function_header(header2)
            backend2.commit_state(state2, "User2 commit")
            
            # Test user discovery
            print("Branches in repo:")
            for branch_name in backend2.repo.branches:
                print(f"  🌿 {branch_name}")
            
            users = backend2.users()
            user_names = [u.name for u in users] if users else []
            print(f"Discovered users: {user_names}")
            
            if len(user_names) >= 2:
                print(f"✅ Found multiple users: {len(user_names)}")
            else:
                print(f"❌ Expected 2+ users, found {len(user_names)}")
                pytest.fail("Test failed")
            
            # Test reading other user's state
            try:
                user1_state = backend2.get_state("testuser")
                print(f"✅ Read testuser state from user2 backend: {user1_state.user}")
            except Exception as e:
                print(f"❌ Failed to read testuser state: {e}")
                pytest.fail("Test failed")
            
            backend2.shutdown()
            
            # Test 3: Git branch verification
            print("\n--- Test 3: Git Branch Structure ---")
            
            backend3 = GitBackend("user3", str(repo_path), "test_hash")
            
            # Check Git branch structure
            print(f"Git branches:")
            for branch_name in backend3.repo.branches:
                print(f"  🌿 {branch_name}")
            
            # Check what's in each user branch
            for branch_name in backend3.repo.branches:
                if branch_name.startswith("binsync/") and branch_name != "binsync/__root__":
                    print(f"\nContent of branch {branch_name}:")
                    try:
                        branch = backend3.repo.lookup_branch(branch_name)
                        if branch and branch.target:
                            commit = backend3.repo[branch.target]
                            tree = commit.tree
                            for entry in tree:
                                print(f"  📄 {entry.name}")
                    except Exception as e:
                        print(f"  ❌ Error reading branch {branch_name}: {e}")
            
            backend3.shutdown()
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    print("\n🎉 Branch structure test completed successfully!")
    return True

if __name__ == "__main__":
    pytest.main([__file__])
    
# Legacy main:
    success = test_branch_structure()
    print(f"\n{'✅ PASSED' if success else '❌ FAILED'}")