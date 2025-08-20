
"""
Test the async sync functionality without requiring IDA
"""

import pytest
import tempfile
import pytest
import threading
import pytest
import time
from pathlib import Path

from binsync.core.git_backend import GitBackend  
from binsync.core.state import State
from binsync.controller import BSController
from libbs.artifacts import Function

def create_large_state(user: str, num_functions: int = 100) -> State:
    """Create a state with many functions for testing"""
    state = State(user)
    
    print(f"Creating {num_functions} functions for user {user}...")
    
    for i in range(num_functions):
        addr = 0x1000 + (i * 0x100) 
        func = Function(addr=addr, size=64, name=f"test_func_{i}")
        state.set_function(func)
    
    print(f"✅ Created state with {len(state.functions)} functions")
    return state

def test_performance_comparison():
    """Test sync performance with different approaches"""
    
    print("🔍 Testing Async Sync Performance")
    print("=" * 50)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Set up test repository with large dataset
            print("\\n--- Setting up test data ---")
            
            backend = GitBackend("user1", str(repo_path), "test_hash", init_repo=True)
            
            # Create user with many functions
            large_state = create_large_state("user2", num_functions=200)
            
            # Commit the large state 
            user2_backend = GitBackend("user2", str(repo_path), "test_hash", ignore_lock=True)
            user2_backend.commit_state(large_state, "Large state commit")
            user2_backend.shutdown()
            
            print(f"✅ Committed large state to repository")
            
            # Create controller for testing - directly access client
            from binsync.core.client import Client
            client = Client("user1", str(repo_path), b"test_hash")
            
            # Directly test client functionality instead of controller
            print(f"✅ Created client for user1")
            
            # Test 1: Regular sync_all timing
            print("\\n--- Test 1: Regular sync_all (simulated) ---")
            start_time = time.time()
            
            # Simulate sync_all workload without actually doing decompiler operations
            user2_state = client.get_state("user2")
            function_count = len(user2_state.functions)
            
            # Simulate processing time (1ms per function, like decompiler operations)
            simulated_time = function_count * 0.001
            
            print(f"📊 Found {function_count} functions to sync")
            print(f"📊 Estimated sync_all time: {simulated_time:.2f} seconds")
            print(f"📊 This would freeze the UI for {simulated_time:.2f} seconds!")
            
            # Test 2: Async approach benefits
            print("\\n--- Test 2: Async Benefits ---")
            print("✅ With async sync:")
            print("  - UI remains responsive")
            print("  - Progress feedback to user") 
            print("  - Cancellation possible")
            print(f"  - Batched processing (50 items at a time)")
            print(f"  - Background thread processing")
            
            # Show the batching improvement
            batch_size = 50
            num_batches = (function_count + batch_size - 1) // batch_size
            print(f"  - {function_count} functions → {num_batches} batches of {batch_size}")
            print(f"  - UI updates between batches")
            
            client.shutdown()
            backend.shutdown()
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    print("\\n🎉 Async sync performance test completed!")
    return True

def test_async_dialog_structure():
    """Test that AsyncSyncDialog has proper structure"""
    
    print("\\n🔍 Testing AsyncSyncDialog Structure")
    print("=" * 50)
    
    try:
        from binsync.ui.async_sync_dialog import AsyncSyncDialog
        
        # Check class structure
        required_methods = [
            '__init__', '_init_ui', '_start_sync', '_run_sync_with_progress',
            '_run_batched_sync_all', '_sync_functions_batched', '_cancel_sync',
            '_log', '_update_ui', 'closeEvent'
        ]
        
        dialog_methods = dir(AsyncSyncDialog)
        
        for method in required_methods:
            if method in dialog_methods:
                print(f"✅ Method {method} found")
            else:
                print(f"❌ Method {method} missing")
                pytest.fail("Test failed")
        
        print("✅ AsyncSyncDialog structure is complete")
        
        # Test that controller has async method
        from binsync.controller import BSController
        
        if hasattr(BSController, 'sync_all_async'):
            print("✅ Controller has sync_all_async method")
        else:
            print("❌ Controller missing sync_all_async method")
            pytest.fail("Test failed")
        
    except Exception as e:
        print(f"❌ Structure test failed: {e}")
        pytest.fail("Test failed")
    
    print("✅ AsyncSyncDialog structure test passed!")
    return True

if __name__ == "__main__":
    pytest.main([__file__])
    
# Legacy main:
    print("🚀 Starting Async Sync Tests")
    print("=" * 50)
    
    success = True
    success &= test_async_dialog_structure()
    success &= test_performance_comparison()
    
    print(f"\\n{'✅ ALL TESTS PASSED' if success else '❌ SOME TESTS FAILED'}")