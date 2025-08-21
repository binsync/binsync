"""
Test corruption detection and automatic fixes.
"""

import tempfile
import logging
import os
from pathlib import Path
import pytest

from binsync.core.git_backend import GitBackend
from binsync.core.state import State
from libbs.artifacts import FunctionHeader

def test_corruption_detection():
    """Test corruption detection and automatic fixes"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Test 1: Create clean repository 
            print("\n--- Test 1: Clean Repository ---")
            
            backend = GitBackend("user1", str(repo_path), "test_hash", init_repo=True)
            
            # Check corruption status (should be clean)
            corruption_report = backend.detect_repo_corruption()
            assert not corruption_report['corrupted'], f"Unexpected corruption: {corruption_report['issues']}"
            
            backend.shutdown()
            
            # Test 2: Simulate branch corruption
            print("\n--- Test 2: Branch Corruption Simulation ---")
            
            # Connect as user1 but force checkout to a different branch
            backend2 = GitBackend("user1", str(repo_path), "test_hash")
            
            # Create user2 branch 
            user2_backend = GitBackend("user2", str(repo_path), "test_hash", ignore_lock=True)
            state2 = State("user2", client=user2_backend)
            header2 = FunctionHeader(name="func2", addr=0x2000, type_="void")
            state2.set_function_header(header2)
            user2_backend.commit_state(state2, "User2 commit")
            user2_backend.shutdown()
            
            # Now checkout user1 backend to user2's branch (simulate corruption)
            user2_branch = backend2.repo.lookup_branch("binsync/user2")
            if user2_branch:
                backend2.repo.checkout(user2_branch)
                print("🔀 Simulated branch corruption: checked out to wrong branch")
            
            # Detect corruption
            corruption_report = backend2.detect_repo_corruption()
            assert corruption_report['corrupted'], "Failed to detect simulated branch corruption"
            
            print(f"Issues found: {corruption_report['issues']}")
            
            # Test automatic fix
            print("🔧 Attempting automatic fix...")
            backend2._attempt_corruption_fix(corruption_report)
            
            # Verify fix
            post_fix_report = backend2.detect_repo_corruption()
            print(f"Post-fix corruption status: {post_fix_report['corrupted']}")
            if post_fix_report['corrupted']:
                print(f"⚠️ Some issues remain: {post_fix_report['issues']}")
            else:
                print("✅ Corruption automatically fixed!")
            
            backend2.shutdown()
            
            # Test 3: Test state user validation
            print("\n--- Test 3: State User Validation ---")
            
            backend3 = GitBackend("user1", str(repo_path), "test_hash")
            
            # Get user1's state (should work correctly)
            user1_state = backend3.get_state("user1")
            assert user1_state.user == "user1", f"Wrong user in state: expected user1, got {user1_state.user}"
            
            # Get user2's state (should work correctly and not affect user1)
            user2_state = backend3.get_state("user2")
            assert user2_state.user == "user2", f"Wrong user in user2 state: expected user2, got {user2_state.user}"
            
            # Verify user1's state is still correct after reading user2
            user1_state_again = backend3.get_state("user1")
            assert user1_state_again.user == "user1", f"User1 state corrupted after reading user2: expected user1, got {user1_state_again.user}"
            
            backend3.shutdown()
            
            # Test 4: Commit validation 
            print("\n--- Test 4: Commit Validation ---")
            
            backend4 = GitBackend("user1", str(repo_path), "test_hash")
            
            # This should work - committing user1's own state
            state1 = State("user1", client=backend4)
            header1 = FunctionHeader(name="func1_updated", addr=0x1000, type_="int")
            state1.set_function_header(header1)
            
            success = backend4.commit_state(state1, "Valid commit")
            assert success, "Valid commit should succeed"
            
            # This should fail - trying to commit another user's state
            state2_wrong = State("user2", client=backend4)
            with pytest.raises(Exception):
                backend4.commit_state(state2_wrong, "Invalid commit")
            
            backend4.shutdown()
            
        except Exception as e:
            pytest.fail(f"Test failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__])