import logging
import os
import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import tempfile
import shutil

import pygit2

from binsync.core.user import User
from binsync.core.state import State, toml_file_to_dict
from binsync.core.errors import MetadataNotFoundError

l = logging.getLogger(__name__)

MAIN_BRANCH = 'binsync/main'
DEFAULT_REMOTE_NAME = 'origin'


class ConflictInfo:
    """Information about a detected conflict"""
    def __init__(self, committer: str, commit_time: datetime.datetime, artifact_path: str):
        self.committer = committer
        self.commit_time = commit_time
        self.artifact_path = artifact_path
        
    def __str__(self):
        return f"Conflict from {self.committer} at {self.commit_time} in {self.artifact_path}"


class Client:
    """
    Simplified Git client using libgit2 for single-branch collaboration.
    All users work on the same `binsync/main` branch with latest-wins conflict resolution.
    """
    
    def __init__(
        self,
        user: str,
        repo_path: str,
        binary_hash: bytes,
        remote_url: Optional[str] = None,
        init_repo: bool = False,
        **kwargs
    ):
        self.user = user
        self.repo_path = Path(repo_path)
        self.repo_root = str(repo_path)  # For compatibility with State.dump()
        self.binary_hash = binary_hash
        self.remote_url = remote_url
        
        # Initialize repository
        if init_repo:
            self.repo = self._init_repository()
        else:
            self.repo = self._open_repository()
            
        self._current_state: Optional[State] = None
        self._last_pull_time: Optional[datetime.datetime] = None
        self._last_push_time: Optional[datetime.datetime] = None
        
        # Load initial state
        try:
            self.pull_and_update()
        except Exception as e:
            l.warning(f"Initial state load failed: {e}")
            self._current_state = State(self.user, client=self)
        
    def _init_repository(self) -> pygit2.Repository:
        """Initialize a new BinSync repository"""
        if self.remote_url:
            # Clone from remote
            repo = pygit2.clone_repository(self.remote_url, str(self.repo_path))
            
            # Check if main branch exists, create if not
            try:
                repo.lookup_branch(MAIN_BRANCH)
            except KeyError:
                # Create main branch
                signature = pygit2.Signature(self.user, f"{self.user}@binsync.local")
                tree = repo.TreeBuilder().write()
                
                # Initial commit
                initial_commit = repo.create_commit(
                    f"refs/heads/{MAIN_BRANCH}",
                    signature,
                    signature,
                    "Initial BinSync commit",
                    tree,
                    []
                )
                
                # Store binary hash
                self._store_binary_hash(repo)
        else:
            # Create local repository
            repo = pygit2.init_repository(str(self.repo_path))
            
            # Create main branch and initial commit
            signature = pygit2.Signature(self.user, f"{self.user}@binsync.local")
            
            # Create binary_hash file
            hash_path = self.repo_path / "binary_hash"
            hash_path.write_text(str(self.binary_hash))
            
            # Add to index and commit
            repo.index.add("binary_hash")
            repo.index.write()
            
            tree = repo.index.write_tree()
            initial_commit = repo.create_commit(
                f"refs/heads/{MAIN_BRANCH}",
                signature,
                signature,
                "Initial BinSync commit",
                tree,
                []
            )
            
            # Set HEAD to main branch
            repo.set_head(f"refs/heads/{MAIN_BRANCH}")
            
        return repo
        
    def _open_repository(self) -> pygit2.Repository:
        """Open existing repository"""
        try:
            repo = pygit2.Repository(str(self.repo_path))
            
            # Verify this is a BinSync repo
            try:
                main_ref = repo.lookup_branch(MAIN_BRANCH)
                if not main_ref:
                    raise Exception(f"Not a BinSync repository - missing {MAIN_BRANCH} branch")
            except KeyError:
                raise Exception(f"Not a BinSync repository - missing {MAIN_BRANCH} branch")
                
            # Verify binary hash matches
            stored_hash = self._get_stored_binary_hash(repo)
            if stored_hash != str(self.binary_hash):
                l.warning(f"Binary hash mismatch: stored={stored_hash}, current={self.binary_hash}")
                
            return repo
            
        except pygit2.GitError as e:
            raise Exception(f"Failed to open BinSync repository: {e}")
            
    def _get_stored_binary_hash(self, repo: pygit2.Repository) -> str:
        """Get the stored binary hash from the repository"""
        try:
            main_branch = repo.lookup_branch(MAIN_BRANCH)
            commit = repo.get(main_branch.target)
            tree = repo.get(commit.tree_id)
            hash_entry = tree["binary_hash"]
            blob = repo.get(hash_entry.id)
            return blob.data.decode().strip()
        except (KeyError, pygit2.GitError):
            return ""
            
    def _store_binary_hash(self, repo: pygit2.Repository):
        """Store binary hash in repository"""
        hash_path = self.repo_path / "binary_hash"
        hash_path.write_text(str(self.binary_hash))
        
    def get_state(self) -> State:
        """Get the current state from the main branch"""
        if self._current_state is None:
            self._current_state = self._load_state_from_branch()
        return self._current_state
        
    def _load_state_from_branch(self) -> State:
        """Load state from the main branch"""
        try:
            main_branch = self.repo.lookup_branch(MAIN_BRANCH)
            commit = self.repo.get(main_branch.target)
            tree = self.repo.get(commit.tree_id)
            
            # Parse state from tree
            state = State.parse(tree, client=self)
            return state
            
        except (KeyError, pygit2.GitError, MetadataNotFoundError):
            # Create new empty state if none exists
            return State(self.user, client=self)
            
    def commit_state(self, state: State, message: Optional[str] = None) -> bool:
        """Commit state changes to the main branch with conflict detection"""
        if not state.dirty:
            return False
            
        # Check for conflicts before committing
        conflicts = self._detect_conflicts()
        if conflicts:
            for conflict in conflicts:
                l.info(f"Detected conflict: {conflict}")
                
        # Always use latest-wins strategy - just commit our changes
        try:
            # Dump state to working directory
            state.dump(self.repo_path)
            
            # Stage all changes
            self.repo.index.add_all()
            self.repo.index.write()
            
            # Create commit
            signature = pygit2.Signature(self.user, f"{self.user}@binsync.local")
            tree = self.repo.index.write_tree()
            
            parent_commits = []
            try:
                main_branch = self.repo.lookup_branch(MAIN_BRANCH)
                if main_branch:
                    parent_commits = [main_branch.target]
            except KeyError:
                pass
                
            commit_message = message or state.last_commit_msg or "Updated artifacts"
            
            commit_id = self.repo.create_commit(
                f"refs/heads/{MAIN_BRANCH}",
                signature,
                signature,
                commit_message,
                tree,
                parent_commits
            )
            
            state._dirty = False
            self._current_state = state
            
            l.debug(f"Committed state: {commit_message}")
            return True
            
        except pygit2.GitError as e:
            l.error(f"Failed to commit state: {e}")
            return False
            
    def _detect_conflicts(self) -> List[ConflictInfo]:
        """Detect potential conflicts by checking recent commits"""
        conflicts = []
        
        try:
            main_branch = self.repo.lookup_branch(MAIN_BRANCH)
            if not main_branch:
                return conflicts
                
            # Look at recent commits to detect overlapping changes
            walker = self.repo.walk(main_branch.target)
            walker.sort(pygit2.GIT_SORT_TIME)
            
            recent_threshold = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(minutes=5)
            
            for commit in walker:
                commit_time = datetime.datetime.fromtimestamp(commit.commit_time, tz=datetime.timezone.utc)
                if commit_time < recent_threshold:
                    break
                    
                if commit.committer.name != self.user:
                    # Simplified conflict detection - just note that there was a recent commit from another user
                    conflict = ConflictInfo(
                        committer=commit.committer.name,
                        commit_time=commit_time,
                        artifact_path="recent_commit"
                    )
                    conflicts.append(conflict)
                        
        except (pygit2.GitError, IndexError):
            pass
            
        return conflicts
        
    def pull_and_update(self) -> bool:
        """Pull changes from remote and update local state"""
        if not self.remote_url:
            # No remote configured, just load local state
            self._current_state = self._load_state_from_branch()
            return True
            
        try:
            # Fetch from remote
            remote = self.repo.remotes[DEFAULT_REMOTE_NAME]
            remote.fetch()
            
            # Get remote main branch
            remote_main_ref = self.repo.lookup_reference(f"refs/remotes/{DEFAULT_REMOTE_NAME}/{MAIN_BRANCH}")
            remote_commit = self.repo.get(remote_main_ref.target)
            
            # Fast-forward merge to remote HEAD
            main_branch = self.repo.lookup_branch(MAIN_BRANCH)
            if main_branch:
                main_branch.set_target(remote_commit.id)
            else:
                # Create local main branch tracking remote
                self.repo.create_branch(MAIN_BRANCH, remote_commit)
                
            # Checkout the updated branch
            self.repo.checkout_tree(remote_commit)
            self.repo.set_head(f"refs/heads/{MAIN_BRANCH}")
            
            # Reload state from updated branch
            self._current_state = self._load_state_from_branch()
            self._last_pull_time = datetime.datetime.now(tz=datetime.timezone.utc)
            
            l.debug("Successfully pulled and updated from remote")
            return True
            
        except (pygit2.GitError, KeyError) as e:
            l.error(f"Failed to pull from remote: {e}")
            return False
            
    def push_changes(self) -> bool:
        """Push local changes to remote"""
        if not self.remote_url:
            return True  # No remote to push to
            
        try:
            remote = self.repo.remotes[DEFAULT_REMOTE_NAME]
            
            # Push main branch
            remote.push([f"refs/heads/{MAIN_BRANCH}:refs/heads/{MAIN_BRANCH}"])
            
            self._last_push_time = datetime.datetime.now(tz=datetime.timezone.utc)
            l.debug("Successfully pushed changes to remote")
            return True
            
        except pygit2.GitError as e:
            l.error(f"Failed to push to remote: {e}")
            return False
            
    def get_users(self) -> List[User]:
        """Get list of users who have committed to this repository"""
        users = set()
        
        try:
            main_branch = self.repo.lookup_branch(MAIN_BRANCH)
            if not main_branch:
                return [User(name=self.user)]
                
            walker = self.repo.walk(main_branch.target)
            for commit in walker:
                users.add(commit.committer.name)
                
        except pygit2.GitError:
            pass
            
        return [User(name=user) for user in users]
        
    def shutdown(self):
        """Cleanup resources"""
        if hasattr(self, 'repo'):
            del self.repo