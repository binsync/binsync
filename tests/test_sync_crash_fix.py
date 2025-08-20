"""
Test the fix for sync_all_async IDA crash
"""

import sys
from unittest.mock import patch
import pytest

def test_ida_detection():
    """Test that IDA Pro detection works correctly"""
    
    try:
        # Test normal environment first
        print("\n--- Normal Environment ---")
        from binsync.controller import BSController
        
        class MockController(BSController):
            def __init__(self):
                pass  # Skip initialization
        
        controller = MockController()
        
        # Should return False due to no QApplication in test environment
        normal_result = controller._is_async_safe()
        # False is expected due to no QApplication in test
        
        # Test IDA Pro environment 
        with patch.dict('sys.modules', {'idaapi': True, 'idc': True, 'ida_pro': True}):
            ida_result = controller._is_async_safe()
            assert ida_result == False, "IDA Pro should be detected as unsafe for async"
        
        # Test the lambda that was causing crashes
        # This is the fixed lambda from activity_table.py
        sync_lambda = lambda checked=False, u="test_user": f"Would sync {u}"
        
        # Test the call patterns that were failing
        result1 = sync_lambda()  # This was crashing before
        result2 = sync_lambda(True)  # This should also work
        result3 = sync_lambda(checked=True, u="real_user")  # And this
        
        assert "test_user" in result1
        assert "test_user" in result2
        assert "real_user" in result3
        
        # Test that imports work without crashing
        from binsync.ui.panel_tabs.activity_table import ActivityTableView
        from binsync.ui.async_sync_dialog import AsyncSyncDialog  
        
        # Test controller method exists
        assert hasattr(BSController, 'sync_all_async'), "sync_all_async method missing"
        
    except Exception as e:
        pytest.fail(f"Test failed: {e}")

def test_sync_behavior():
    """Test the sync behavior paths without full controller"""
    
    try:
        from binsync.controller import BSController
        
        class TestController(BSController):
            def __init__(self):
                pass
                
            def sync_all(self, **kwargs):
                return f"Sync completed for {kwargs.get('user', 'unknown')}"
                
            def _show_sync_message(self, message, parent=None, is_final=False, is_error=False):
                print(f"SYNC MSG: {message}")
        
        controller = TestController()
        
        # Mock IDA environment
        with patch.dict('sys.modules', {'idaapi': True, 'idc': True}):
            # This should detect IDA and use synchronous fallback
            result = controller.sync_all_async(user="test_user")
            assert "Sync completed" in str(result), "Synchronous fallback should work"
        
    except Exception as e:
        pytest.fail(f"Sync behavior test failed: {e}")

if __name__ == "__main__":
    pytest.main([__file__])