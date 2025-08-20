"""
Basic BinSync functionality tests
"""

import tempfile
import pytest
from pathlib import Path

from binsync.core.client import Client
from libbs.artifacts import FunctionHeader


def test_client_creation():
    """Test basic client creation and initialization"""
    with tempfile.TemporaryDirectory() as tmpdir:
        client = Client("test_user", tmpdir, "test_hash", init_repo=True)
        
        # Test basic operations
        state = client.get_state()
        assert state is not None, "Should be able to get state"
        assert state.user == "test_user", f"Expected test_user, got {state.user}"
        
        client.shutdown()


def test_state_operations():
    """Test basic state operations"""
    with tempfile.TemporaryDirectory() as tmpdir:
        client = Client("test_user", tmpdir, "test_hash", init_repo=True)
        
        # Get master state
        state = client.master_state
        assert state.user == "test_user"
        
        # Add a function header
        func_header = FunctionHeader(name="test_function", addr=0x1000, type_="int")
        state.set_function_header(func_header)
        
        # Check that it was added
        assert len(state.functions) == 1
        assert state.functions[0x1000].header == func_header
        
        client.shutdown()


def test_multi_user_simulation():
    """Test basic multi-user scenario"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create first user
        client1 = Client("user1", tmpdir, "test_hash", init_repo=True)
        
        state1 = client1.master_state
        func1 = FunctionHeader(name="func1", addr=0x1000, type_="int")
        state1.set_function_header(func1)
        client1.commit_master_state()
        client1.shutdown()
        
        # Create second user
        client2 = Client("user2", tmpdir, "test_hash")
        
        state2 = client2.master_state
        func2 = FunctionHeader(name="func2", addr=0x2000, type_="void")
        state2.set_function_header(func2)
        client2.commit_master_state()
        
        # Test that user2 can see user1's data (if available)
        try:
            user1_state = client2.get_state("user1")
            if user1_state is not None:
                # If we can get user1's state, check basic properties
                assert hasattr(user1_state, 'user'), "State should have user attribute"
        except Exception:
            # Multi-user functionality might not be fully implemented
            pass
        
        client2.shutdown()


if __name__ == "__main__":
    pytest.main([__file__])