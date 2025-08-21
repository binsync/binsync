
"""
Test checkout optimization - verify we only checkout to master user's branch
and can read other users' data directly from Git objects.
"""

import pytest
import tempfile
import pytest
import logging
from pathlib import Path

# Enable logging to see checkout operations
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s | %(name)s | %(message)s')

from binsync.core.git_backend import GitBackend
from binsync.core.state import State
from libbs.artifacts import FunctionHeader

def test_checkout_optimization():
    """Test that we minimize checkouts and read from Git objects efficiently"""
    
    print("⚡ Testing Checkout Optimization")
    print("=" * 40)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Test 1: Create repository with multiple users
            print("\n--- Test 1: Create Multi-User Repository ---")
            
            # Create user1 (will be master for this test)
            user1_backend = GitBackend("user1", str(repo_path), "test_hash", init_repo=True)
            
            # Add state for user1 
            state1 = State("user1", client=user1_backend)
            header1 = FunctionHeader(name="func1", addr=0x1000, type_="int")
            state1.set_function_header(header1)
            user1_backend.commit_state(state1, "User1 initial commit")
            
            # Check what branch we're on
            current_branch = user1_backend.repo.head.shorthand
            print(f"✅ User1 backend is on branch: {current_branch}")
            
            user1_backend.shutdown()
            
            # Create user2 
            user2_backend = GitBackend("user2", str(repo_path), "test_hash")
            
            state2 = State("user2", client=user2_backend)
            header2 = FunctionHeader(name="func2", addr=0x2000, type_="void")
            state2.set_function_header(header2)
            user2_backend.commit_state(state2, "User2 initial commit")
            
            current_branch = user2_backend.repo.head.shorthand
            print(f"✅ User2 backend is on branch: {current_branch}")
            
            user2_backend.shutdown()
            
            # Create user3
            user3_backend = GitBackend("user3", str(repo_path), "test_hash")
            
            state3 = State("user3", client=user3_backend)
            header3 = FunctionHeader(name="func3", addr=0x3000, type_="char*")
            state3.set_function_header(header3)
            user3_backend.commit_state(state3, "User3 initial commit")
            
            current_branch = user3_backend.repo.head.shorthand
            print(f"✅ User3 backend is on branch: {current_branch}")
            
            user3_backend.shutdown()
            
            print("✅ Created repository with 3 users")
            
            # Test 2: Connect as user1 and read other users' data without checkout
            print("\n--- Test 2: Read Other Users' Data (No Checkout) ---")
            
            # Connect as user1 (master)
            master_backend = GitBackend("user1", str(repo_path), "test_hash")
            
            # Verify we're on user1's branch
            current_branch = master_backend.repo.head.shorthand
            print(f"✅ Master backend on branch: {current_branch}")
            expected_branch = master_backend.user_branch_name  # Full branch name
            assert current_branch == expected_branch, f"Expected {expected_branch}, got {current_branch}"
            
            # Get all users (should see all 3)
            users = master_backend.users()
            user_names = [u.name for u in users] if users else []
            print(f"✅ Visible users: {user_names}")
            assert len(user_names) == 3, f"Expected 3 users, got {len(user_names)}"
            
            # Test reading each user's state without checkout
            for user_name in ["user1", "user2", "user3"]:
                print(f"\n  Testing state read for {user_name}:")
                
                # Record current branch before state read
                branch_before = master_backend.repo.head.shorthand
                print(f"    Branch before read: {branch_before}")
                
                # Read user state 
                user_state = master_backend.get_state(user_name)
                print(f"    ✅ Got state for {user_name}: {user_state.user}")
                
                # Verify branch hasn't changed (except for master user)
                branch_after = master_backend.repo.head.shorthand
                print(f"    Branch after read: {branch_after}")
                
                if user_name == "user1":  # Master user
                    print(f"    ✅ Master user - branch unchanged: {branch_before == branch_after}")
                else:  # Other users 
                    assert branch_before == branch_after, f"Branch changed from {branch_before} to {branch_after} when reading {user_name}"
                    print(f"    ✅ Other user - no checkout performed")
            
            # Final verification we're still on master branch
            final_branch = master_backend.repo.head.shorthand
            print(f"\n✅ Final branch check: {final_branch} (should be {expected_branch})")
            assert final_branch == expected_branch, f"Final branch {final_branch} != expected {expected_branch}"
            
            master_backend.shutdown()
            
            # Test 3: Test pull operations don't cause unnecessary checkouts
            print("\n--- Test 3: Test Pull Operations ---")
            
            test_backend = GitBackend("user2", str(repo_path), "test_hash")
            
            # Check initial branch
            initial_branch = test_backend.repo.head.shorthand 
            print(f"Initial branch: {initial_branch}")
            
            # Test pull (should not change our branch since no remote)
            pull_result = test_backend.pull()
            print(f"Pull result: {pull_result}")
            
            # Check branch after pull
            after_pull_branch = test_backend.repo.head.shorthand
            print(f"Branch after pull: {after_pull_branch}")
            
            expected_user2_branch = test_backend.user_branch_name  # Full branch name
            assert after_pull_branch == expected_user2_branch, f"Branch changed unexpectedly during pull"
            print(f"✅ Pull operations maintain correct branch")
            
            test_backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    print("\n🎉 Checkout optimization test completed successfully!")
    return True

if __name__ == "__main__":
    pytest.main([__file__])
    
# Legacy main:
    success = test_checkout_optimization()
    print(f"\n{'✅ PASSED' if success else '❌ FAILED'}")