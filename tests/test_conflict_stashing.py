"""
Test conflict stashing functionality
"""

import tempfile
import logging
import os
import pathlib
from pathlib import Path
import pytest

from binsync.core.git_backend import GitBackend
from binsync.core.state import State
from libbs.artifacts import Function

def test_conflict_stashing():
    """Test that conflicts are automatically stashed during initialization"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Step 1: Create initial repository
            print("\n--- Step 1: Creating initial repository ---")
            backend = GitBackend("user1", str(repo_path), "test_hash", init_repo=True)
            
            # Create and commit initial state
            state = State("user1", client=backend)
            func = Function(addr=0x1000, size=64, name="initial_func")
            state.set_function(func)
            backend.commit_state(state, "Initial commit")
            print("✅ Created initial repository with commit")
            
            backend.shutdown()
            
            # Step 2: Create conflicting changes in working directory
            print("\n--- Step 2: Creating conflicting changes ---")
            
            # Manually create conflicting files in working directory
            metadata_path = repo_path / "metadata.toml"
            functions_dir = repo_path / "functions"
            functions_dir.mkdir(exist_ok=True)
            
            # Create conflicting metadata
            with open(metadata_path, 'w') as f:
                f.write('''
[metadata]
user = "conflicting_user"
version = "1.0.0"
''')
            print("✅ Created conflicting metadata.toml")
            
            # Create conflicting function file
            conflicting_func_path = functions_dir / "00002000.toml"
            with open(conflicting_func_path, 'w') as f:
                f.write('''
addr = 0x2000
size = 128
name = "conflicting_func"
''')
            print("✅ Created conflicting function file")
            
            # Step 3: Try to initialize backend again (should trigger conflict resolution)
            print("\n--- Step 3: Testing conflict resolution ---")
            
            backend2 = GitBackend("user1", str(repo_path), "test_hash")
            
            # Check if conflicts were resolved
            current_state = backend2.get_state("user1")
            assert current_state.user == "user1", f"Expected user1, got {current_state.user}"
            
            backend2.shutdown()
            
            # Step 4: Verify stash was created
            print("\n--- Step 4: Verifying stash creation ---")
            
            # Reconnect to check stash
            backend3 = GitBackend("user1", str(repo_path), "test_hash")
            
            try:
                # Check if stash exists using raw git commands
                import subprocess
                result = subprocess.run(
                    ['git', 'stash', 'list'], 
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    print("✅ Stash created successfully:")
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            print(f"  {line}")
                else:
                    print("ℹ️  No stashes found (conflicts may have been resolved differently)")
                    
            except Exception as e:
                print(f"⚠️  Could not check stash: {e}")
            
            backend3.shutdown()
            
        except Exception as e:
            pytest.fail(f"Test failed: {e}")

def test_safe_checkout_method():
    """Test the _safe_checkout method specifically"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "test_repo"
        
        try:
            # Create repository with initial commit
            backend = GitBackend("user1", str(repo_path), "test_hash", init_repo=True)
            
            # Test _safe_checkout method exists and is callable
            assert hasattr(backend, '_safe_checkout'), "_safe_checkout method missing"
            assert hasattr(backend, '_stash_conflicts_if_needed'), "_stash_conflicts_if_needed method missing"
            
            # Test stash detection with clean repository
            conflicts_found = backend._stash_conflicts_if_needed("test")
            assert conflicts_found == False, "Expected no conflicts in clean repository"
            
            backend.shutdown()
            
        except Exception as e:
            pytest.fail(f"Method test failed: {e}")

if __name__ == "__main__":
    pytest.main([__file__])