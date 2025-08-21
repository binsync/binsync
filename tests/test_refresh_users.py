
"""
Test the refresh_remote_users functionality.
"""

import pytest
import tempfile
import pytest
import logging
from pathlib import Path

# Enable logging to see the refresh messages
logging.basicConfig(level=logging.INFO, format='%(levelname)s | %(name)s | %(message)s')

from binsync.core.client import Client

def test_refresh_users():
    """Test refreshing remote users"""
    
    print("🔄 Testing Remote User Refresh")
    print("=" * 40)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Create client
            client = Client(
                master_user="test_user",
                repo_root=str(repo_path),
                binary_hash="58f7a557eff80c5c254f10047e7e058d",
                init_repo=True
            )
            
            # Test refresh without remote (should handle gracefully)
            print("\nTesting refresh without remote:")
            client.refresh_remote_users()
            
            # Get current users
            users = client.users()
            print(f"Current users: {[u.name for u in users] if users else 'None'}")
            
            client.shutdown()
            print("✅ Refresh users test completed")
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail("Test failed")
    
    return True

if __name__ == "__main__":
    pytest.main([__file__])
    
# Legacy main:
    success = test_refresh_users()
    print(f"\n{'✅ PASSED' if success else '❌ FAILED'}")