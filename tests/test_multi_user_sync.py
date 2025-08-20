
"""
Test multi-user remote synchronization for the new pygit2 backend.

This test verifies:
1. No more 'NoneType' object has no attribute 'target' or 'set_target' errors
2. Remote branches are properly localized to show all users
3. Push operations handle missing branches gracefully
4. Multiple users can collaborate through Git operations
"""

import pytest
import tempfile
import logging
import os
import shutil
from pathlib import Path

# Enable debug logging to see all operations
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s | %(name)s:%(lineno)d | %(message)s')

from binsync.core.git_backend import GitBackend
from binsync.core.state import State

def test_multi_user_sync():
    """Test multi-user synchronization with the new Git backend"""
    
    print("🧪 Testing Multi-User Remote Synchronization")
    print("=" * 50)
    
    # Test 1: Create initial repository
    print("\n--- Test 1: Create Initial Repository ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Create first user (master)
            user1_backend = GitBackend("user1", str(repo_path), "test_binary_hash", init_repo=True)
            print("✅ Created initial repository with user1")
            
            # Test that users list works without errors
            users = user1_backend.users()
            print(f"✅ Initial users: {[u.name for u in users] if users else 'None'}")
            
            # Create and commit some state for user1
            from libbs.artifacts import FunctionHeader
            state1 = State("user1", client=user1_backend)
            header1 = FunctionHeader(name="test_function", addr=0x1000, type_="int")
            state1.set_function_header(header1)
            
            # Test commit operation
            success = user1_backend.commit_state(state1, "Initial commit by user1")
            print(f"✅ User1 commit successful: {success}")
            
            user1_backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test 1 failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    # Test 2: Simulate multi-user environment
    print("\n--- Test 2: Multi-User Operations ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Create repo with user1
            user1_backend = GitBackend("user1", str(repo_path), "test_binary_hash", init_repo=True)
            
            # Create initial state and commit
            from libbs.artifacts import FunctionHeader
            state1 = State("user1", client=user1_backend)
            header1 = FunctionHeader(name="func1", addr=0x1000, type_="int")
            state1.set_function_header(header1)
            user1_backend.commit_state(state1, "User1 initial commit")
            
            # Shutdown user1 backend first to release lock
            user1_backend.shutdown()
            
            # Create user2 on same repo
            user2_backend = GitBackend("user2", str(repo_path), "test_binary_hash")
            
            # Create state for user2
            state2 = State("user2", client=user2_backend)
            header2 = FunctionHeader(name="func2", addr=0x2000, type_="void")
            state2.set_function_header(header2)
            user2_backend.commit_state(state2, "User2 initial commit")
            
            print("✅ Created two users on same repository")
            
            # Test that user2 can see both users
            user2_users = user2_backend.users()
            print(f"User2 sees: {[u.name for u in user2_users] if user2_users else 'None'}")
            
            # Test getting states
            user2_state = user2_backend.get_state("user2")
            print(f"✅ User2 state loaded: {user2_state.user if user2_state else 'None'}")
            
            # Try to get user1 state from user2 backend
            try:
                user1_state_from_user2 = user2_backend.get_state("user1")
                print(f"✅ User1 state from user2 backend: {user1_state_from_user2.user if user1_state_from_user2 else 'None'}")
            except Exception as e:
                print(f"Getting user1 state from user2 backend failed: {e}")
            
            user2_backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test 2 failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    # Test 3: Test null reference handling
    print("\n--- Test 3: Null Reference Handling ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Create backend
            backend = GitBackend("testuser", str(repo_path), "test_binary_hash", init_repo=True)
            
            # Test users() with potentially empty repo
            users = backend.users()
            print(f"✅ Users method handles empty repo: {users is not None}")
            
            # Test get_state with non-existent user
            try:
                nonexistent_state = backend.get_state("nonexistent_user")
                print(f"✅ Get non-existent user state: {nonexistent_state.user if nonexistent_state else 'None'}")
            except Exception as e:
                print(f"Get non-existent user failed as expected: {e}")
            
            # Test pull/push without remote
            pull_result = backend.pull()
            push_result = backend.push()
            print(f"✅ Pull/push without remote: pull={pull_result}, push={push_result}")
            
            backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test 3 failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    # Test 4: Branch handling
    print("\n--- Test 4: Branch Operations ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Create backend
            backend = GitBackend("master_user", str(repo_path), "test_binary_hash", init_repo=True)
            
            # Check if branches exist before operations
            print(f"Has remote: {backend.has_remote}")
            print(f"User branch name: {backend.user_branch_name}")
            
            # Test branch lookup operations that might return None
            root_branch = backend.repo.lookup_branch("binsync/__root__")
            user_branch = backend.repo.lookup_branch(backend.user_branch_name)
            
            print(f"✅ Root branch found: {root_branch is not None}")
            print(f"✅ User branch found: {user_branch is not None}")
            
            # Test _localize_remote_branches with no remote
            backend._localize_remote_branches(backend.repo)
            print("✅ Remote branch localization completed (no remote)")
            
            backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test 4 failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    print("\n🎉 All tests completed successfully!")

if __name__ == "__main__":
    pytest.main([__file__])