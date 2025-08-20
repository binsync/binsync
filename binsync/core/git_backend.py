import logging
import os
import pathlib
import datetime
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Dict, List, Iterable
import subprocess
import platform
import getpass

import pygit2
import filelock
import toml

from binsync.core.user import User
from binsync.core.state import State, toml_file_to_dict
from binsync.core.errors import ExternalUserCommitError, MetadataNotFoundError

l = logging.getLogger(__name__)

BINSYNC_BRANCH_PREFIX = 'binsync'
BINSYNC_ROOT_BRANCH = f'{BINSYNC_BRANCH_PREFIX}/__root__'


class GitBackend:
    """
    Simplified Git backend using pygit2 that replaces the complex GitPython implementation.
    
    Key design principles:
    1. No atomic actions - pygit2 is thread-safe enough for our use case
    2. Simple direct operations without heavy scheduling
    3. Immediate data access for UI - non-master user data can be stale
    4. Master user data is always current and correct
    """
    
    def __init__(
        self,
        master_user: str,
        repo_root: str,
        binary_hash: bytes,
        remote: str = "origin",
        remote_url: Optional[str] = None,
        ssh_agent_pid: Optional[int] = None,
        ssh_auth_sock: Optional[str] = None,
        init_repo: bool = False,
        ignore_lock: bool = False,
    ):
        self.master_user = master_user
        self.repo_root = str(Path(repo_root).resolve())
        self.binary_hash = binary_hash
        self.remote = remote
        self.ssh_agent_pid = ssh_agent_pid
        self.ssh_auth_sock = ssh_auth_sock
        self._ignore_lock = ignore_lock
        
        # Validate username
        if not master_user or master_user.endswith('/') or '__root__' in master_user:
            raise Exception(f"Bad username: {master_user}")
            
        self._repo_lock_path = Path(self.repo_root) / ".git" / "binsync.lock"
        self.repo_lock = None
        self.repo = None
        
        # Initialize or open repository
        try:
            self.repo = self._get_or_init_binsync_repo(remote_url, init_repo)
            self._acquire_repo_lock()
            self._get_or_init_user_branch()
            
            # Detect repository corruption after initialization
            corruption_report = self.detect_repo_corruption()
            if corruption_report["corrupted"]:
                l.warning("Repository corruption detected during initialization!")
                for issue in corruption_report["issues"]:
                    l.warning(f"  - {issue}")
                # Try to fix corruption automatically
                self._attempt_corruption_fix(corruption_report)
        except Exception as e:
            l.error(f"Failed to initialize Git backend: {e}")
            # Clean up any partial state
            if hasattr(self, 'repo_lock') and self.repo_lock:
                try:
                    self.repo_lock.release()
                except:
                    pass
            raise
        
        # Timestamps for tracking
        self._last_push_time = None
        self._last_pull_time = None
        self._last_commit_time = None
        self.last_push_attempt_time = None
        self.last_pull_attempt_time = None
        self.active_remote = True
        
    def _acquire_repo_lock(self):
        """Acquire file lock for repository access"""
        self.repo_lock = filelock.FileLock(str(self._repo_lock_path))
        should_delete_lock = False
        
        try:
            self.repo_lock.acquire(timeout=0)
        except filelock.Timeout as e:
            if not self._ignore_lock:
                raise Exception(
                    "Can only have one binsync client touching a local repository at once.\n"
                    f"If the previous client crashed, you need to delete {self.repo_root}/.git/binsync.lock"
                ) from e
            should_delete_lock = True
            
        if should_delete_lock:
            if self._repo_lock_path.exists():
                self._repo_lock_path.unlink(missing_ok=True)
            self.repo_lock = filelock.FileLock(str(self._repo_lock_path))
            self.repo_lock.acquire(timeout=0)
    
    def _get_or_init_binsync_repo(self, remote_url: Optional[str], init_repo: bool) -> pygit2.Repository:
        """Initialize or open a BinSync repository"""
        if remote_url:
            if not self.repo_root:
                self.repo_root = re.findall(r"/(.*)\.git", remote_url)[0]
                
            repo = self._clone_repository(remote_url, no_head_check=init_repo)
            
            if init_repo:
                if self._has_binsync_root_branch(repo):
                    raise Exception("Can't init this remote repo since a BinSync root already exists")
                self._setup_repo(repo)
        else:
            try:
                l.debug(f"Trying to open existing repository at {self.repo_root}")
                repo = pygit2.Repository(self.repo_root)
                
                if init_repo:
                    raise Exception("Could not initialize repository - it already exists!")
                if not self._has_binsync_root_branch(repo):
                    raise Exception(f"This is not a BinSync repo - it must have a {BINSYNC_ROOT_BRANCH} branch.")
                    
                # Localize remote branches after verifying it's a valid BinSync repo
                self._localize_remote_branches(repo)
            except (pygit2.GitError, FileNotFoundError) as e:
                l.debug(f"Failed to open existing repo: {e}")
                if init_repo:
                    l.debug(f"Initializing new repository at {self.repo_root}")
                    repo = pygit2.init_repository(self.repo_root, False)  # Not bare
                    self._setup_repo(repo)
                else:
                    raise Exception(f"Failed to connect or create a BinSync repo: {e}")
                    
        # Verify binary hash
        try:
            stored_hash = self._get_stored_hash(repo)
            if stored_hash and stored_hash != self.binary_hash:
                l.info(f"Binary hash difference: stored={stored_hash}, expected={self.binary_hash}")
                l.info("This is normal when connecting to a repository for a different binary")
            elif not stored_hash:
                l.debug(f"No stored binary hash found, this may be expected for existing repos")
        except Exception as e:
            l.debug(f"Could not verify binary hash: {e}")
            
        return repo
        
    def _has_binsync_root_branch(self, repo: pygit2.Repository) -> bool:
        """Check if repository has the BinSync root branch"""
        try:
            repo.lookup_branch(BINSYNC_ROOT_BRANCH)
            return True
        except KeyError:
            return False
            
    def _setup_repo(self, repo: pygit2.Repository):
        """Set up a new BinSync repository"""
        # Create .gitignore
        gitignore_path = os.path.join(self.repo_root, ".gitignore")
        with open(gitignore_path, "w") as f:
            f.write(".git/*\n")
            
        # Create binary_hash file
        hash_path = os.path.join(self.repo_root, "binary_hash")
        with open(hash_path, "w") as f:
            f.write(self.binary_hash)
            
        # Add files and commit
        repo.index.add(".gitignore")
        repo.index.add("binary_hash")
        repo.index.write()
        
        signature = self._get_signature()
        tree = repo.index.write_tree()
        repo.create_commit(
            "HEAD",
            signature,
            signature,
            "Root commit",
            tree,
            []
        )
        
        # Create root branch
        head_commit = repo[repo.head.target]
        repo.create_branch(BINSYNC_ROOT_BRANCH, head_commit)
        
    def _get_signature(self) -> pygit2.Signature:
        """Get Git signature for commits"""
        return pygit2.Signature(self.master_user, f"{self.master_user}@binsync")
        
    def _get_or_init_user_branch(self):
        """Create or checkout user branch"""
        branch_name = self.user_branch_name
        
        try:
            branch = self.repo.lookup_branch(branch_name)
            if branch is None:
                # Try remote branch first (if this user already exists remotely)
                try:
                    remote_branch = self.repo.lookup_branch(f"{self.remote}/{branch_name}", pygit2.GIT_BRANCH_REMOTE)
                    if remote_branch and remote_branch.target:
                        remote_commit = self.repo[remote_branch.target]
                        branch = self.repo.create_branch(branch_name, remote_commit)
                        l.info(f"Created user branch {branch_name} from remote")
                    else:
                        raise KeyError("No remote branch")
                except KeyError:
                    # For new users, ALWAYS create from root branch (not from current HEAD/branch)
                    # This prevents new users from inheriting files from whoever was checked out
                    try:
                        root_ref = self.repo.lookup_reference(f"refs/heads/{BINSYNC_ROOT_BRANCH}")
                        if root_ref and root_ref.target:
                            root_commit = self.repo[root_ref.target]
                            branch = self.repo.create_branch(branch_name, root_commit)
                            l.info(f"Created new user branch {branch_name} from root branch (clean start)")
                        else:
                            # Try to find root branch as a remote branch
                            remote_root = self.repo.lookup_branch(f"{self.remote}/{BINSYNC_ROOT_BRANCH}", pygit2.GIT_BRANCH_REMOTE)
                            if remote_root and remote_root.target:
                                root_commit = self.repo[remote_root.target]
                                branch = self.repo.create_branch(branch_name, root_commit)
                                l.info(f"Created new user branch {branch_name} from remote root branch")
                            else:
                                raise KeyError("No root branch found locally or remotely")
                    except KeyError:
                        # Last resort: create from HEAD only if root branch truly doesn't exist
                        # This should be rare and only happen in very early repository states
                        if self.repo.head and self.repo.head.target:
                            head_commit = self.repo[self.repo.head.target]
                            branch = self.repo.create_branch(branch_name, head_commit)
                            l.warning(f"Created user branch {branch_name} from HEAD (no root branch available)")
                            l.warning("This may inherit files from current branch - consider creating root branch")
                        else:
                            # No head - this means empty repo, need to make initial commit
                            l.error("Cannot create user branch: no commits in repository")
                            raise Exception("Repository has no commits to branch from")
        except KeyError:
            # Fallback path - same priority: root branch first, HEAD as last resort
            try:
                root_ref = self.repo.lookup_reference(f"refs/heads/{BINSYNC_ROOT_BRANCH}")
                if root_ref and root_ref.target:
                    root_commit = self.repo[root_ref.target]
                    branch = self.repo.create_branch(branch_name, root_commit)
                    l.info(f"Created user branch {branch_name} from root branch (fallback path)")
                else:
                    raise KeyError("No root branch")
            except KeyError:
                # Create from HEAD only as absolute last resort
                if self.repo.head and self.repo.head.target:
                    head_commit = self.repo[self.repo.head.target]
                    branch = self.repo.create_branch(branch_name, head_commit)
                    l.warning(f"Created user branch {branch_name} from HEAD (last resort)")
                else:
                    l.error("Cannot create user branch: no commits in repository")
                    raise Exception("Repository has no commits to branch from")
            
        if branch:
            self._safe_checkout(branch, f"user branch initialization ({branch_name})")
        else:
            raise Exception(f"Failed to create or find branch {branch_name}")
        
    def _clone_repository(self, remote_url: str, no_head_check: bool = False) -> pygit2.Repository:
        """Clone repository from remote URL"""
        callbacks = pygit2.RemoteCallbacks()
        callbacks.credentials = self._create_credentials_callback()
            
        repo = pygit2.clone_repository(remote_url, self.repo_root, callbacks=callbacks)
        
        if not no_head_check:
            try:
                remote_root = repo.lookup_branch(f"{self.remote}/{BINSYNC_ROOT_BRANCH}", pygit2.GIT_BRANCH_REMOTE)
                if remote_root:
                    remote_commit = repo[remote_root.target]
                    repo.create_branch(BINSYNC_ROOT_BRANCH, remote_commit)
                else:
                    raise Exception(f"This is not a binsync repo - it must have a {BINSYNC_ROOT_BRANCH} branch")
            except KeyError:
                raise Exception(f"This is not a binsync repo - it must have a {BINSYNC_ROOT_BRANCH} branch")
                
        return repo
        
    def _create_credentials_callback(self):
        """Create a comprehensive credentials callback for different auth methods"""
        def credentials_callback(url, username_from_url, allowed_types):
            l.debug(f"Credentials requested for {url}, allowed types: {allowed_types}")
            
            # Try SSH key authentication first (most common for GitHub/GitLab)
            if allowed_types & pygit2.GIT_CREDENTIAL_SSH_KEY:
                try:
                    # Try common SSH key locations
                    ssh_key_paths = self._get_ssh_key_paths()
                    for private_key, public_key in ssh_key_paths:
                        if private_key.exists():
                            l.debug(f"Trying SSH key: {private_key}")
                            try:
                                # Try with no passphrase first
                                return pygit2.Keypair(
                                    username_from_url or "git",
                                    str(public_key) if public_key.exists() else None,
                                    str(private_key),
                                    ""
                                )
                            except Exception as e:
                                l.debug(f"SSH key {private_key} failed: {e}")
                                continue
                except Exception as e:
                    l.debug(f"SSH key authentication failed: {e}")
            
            # Try SSH agent if available
            if allowed_types & pygit2.GIT_CREDENTIAL_SSH_KEY:
                try:
                    l.debug("Trying SSH agent authentication")
                    return pygit2.KeypairFromAgent(username_from_url or "git")
                except Exception as e:
                    l.debug(f"SSH agent authentication failed: {e}")
            
            # Try username/password for HTTPS
            if allowed_types & pygit2.GIT_CREDENTIAL_USERPASS_PLAINTEXT:
                try:
                    # Check for stored credentials first
                    username, password = self._get_stored_credentials(url)
                    if username and password:
                        l.debug(f"Using stored credentials for {username}")
                        return pygit2.UserPass(username, password)
                except Exception as e:
                    l.debug(f"Stored credentials failed: {e}")
            
            # Try default credentials (system git config)
            if allowed_types & pygit2.GIT_CREDENTIAL_DEFAULT:
                try:
                    l.debug("Trying default credentials")
                    return pygit2.credentials.Default()
                except Exception as e:
                    l.debug(f"Default credentials failed: {e}")
            
            l.warning(f"No suitable credentials found for {url}")
            return None
            
        return credentials_callback
        
    def _get_ssh_key_paths(self) -> List[tuple]:
        """Get common SSH key file paths"""
        home = Path.home()
        ssh_dir = home / ".ssh"
        
        key_names = [
            "id_rsa",
            "id_ed25519", 
            "id_ecdsa",
            "id_dsa",
            "github_rsa",
            "gitlab_rsa",
        ]
        
        key_paths = []
        for key_name in key_names:
            private_key = ssh_dir / key_name
            public_key = ssh_dir / f"{key_name}.pub"
            key_paths.append((private_key, public_key))
            
        return key_paths
        
    def _get_stored_credentials(self, url: str) -> tuple:
        """Try to get stored credentials from git config or credential helpers"""
        try:
            # Try to use git credential helper
            import subprocess
            
            # Parse URL to get host
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Try git credential fill
            process = subprocess.Popen(
                ["git", "credential", "fill"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            input_data = f"protocol={parsed.scheme}\nhost={parsed.hostname}\n"
            if parsed.path:
                input_data += f"path={parsed.path}\n"
            input_data += "\n"
            
            stdout, stderr = process.communicate(input=input_data, timeout=10)
            
            if process.returncode == 0:
                # Parse the output
                lines = stdout.strip().split('\n')
                username = None
                password = None
                for line in lines:
                    if line.startswith('username='):
                        username = line[9:]
                    elif line.startswith('password='):
                        password = line[9:]
                
                if username and password:
                    return username, password
                    
        except Exception as e:
            l.debug(f"Failed to get stored credentials: {e}")
            
        return None, None
        
    def _handle_auth_error(self, error: Exception, operation: str):
        """Handle authentication errors with helpful user guidance"""
        error_msg = str(error).lower()
        
        if "authentication required" in error_msg or "no callback set" in error_msg:
            l.error(f"Authentication failed for {operation} operation")
            l.error("")
            l.error("To fix authentication issues:")
            l.error("")
            l.error("For SSH (recommended):")
            l.error("  1. Generate an SSH key: ssh-keygen -t ed25519 -C 'your-email@example.com'")
            l.error("  2. Add the public key to your Git provider (GitHub/GitLab)")
            l.error("  3. Test connection: ssh -T git@github.com")
            l.error("")
            l.error("For HTTPS:")
            l.error("  1. Set up a personal access token in your Git provider")
            l.error("  2. Use git credential manager: git config --global credential.helper store")
            l.error("  3. Or set credentials: git config --global user.name 'username'")
            l.error("")
            l.error("Common SSH key locations checked:")
            for private_key, public_key in self._get_ssh_key_paths():
                status = "✓" if private_key.exists() else "✗"
                l.error(f"  {status} {private_key}")
                
        elif "connection refused" in error_msg:
            l.error(f"Network connection failed for {operation} operation")
            l.error("Check your internet connection and try again")
            
        elif "repository not found" in error_msg or "not found" in error_msg:
            l.error(f"Repository not found during {operation} operation")
            l.error("Check that the repository URL is correct and you have access")
            
        else:
            l.error(f"Git {operation} failed: {error}")
            
    def get_auth_status(self) -> Dict[str, any]:
        """Get authentication status and recommendations"""
        status = {
            "ssh_keys_found": [],
            "ssh_agent_running": False,
            "git_credential_helper": None,
            "recommendations": []
        }
        
        # Check for SSH keys
        for private_key, public_key in self._get_ssh_key_paths():
            if private_key.exists():
                status["ssh_keys_found"].append({
                    "private_key": str(private_key),
                    "public_key": str(public_key) if public_key.exists() else None,
                    "has_public_key": public_key.exists()
                })
        
        # Check if SSH agent is running
        try:
            result = subprocess.run(["ssh-add", "-l"], capture_output=True, text=True, timeout=5)
            status["ssh_agent_running"] = result.returncode == 0
        except Exception:
            status["ssh_agent_running"] = False
            
        # Check git credential helper
        try:
            result = subprocess.run(["git", "config", "--global", "credential.helper"], 
                                   capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                status["git_credential_helper"] = result.stdout.strip()
        except Exception:
            pass
            
        # Generate recommendations
        if not status["ssh_keys_found"]:
            status["recommendations"].append(
                "Generate an SSH key: ssh-keygen -t ed25519 -C 'your-email@example.com'"
            )
            
        if status["ssh_keys_found"] and not status["ssh_agent_running"]:
            status["recommendations"].append(
                "Start SSH agent and add your key: ssh-add ~/.ssh/id_ed25519"
            )
            
        if not status["git_credential_helper"]:
            status["recommendations"].append(
                "Set up credential helper: git config --global credential.helper store"
            )
            
        return status
        
    def _localize_remote_branches(self, repo: pygit2.Repository):
        """Create local tracking branches for remote branches"""
        if not self.has_remote:
            l.debug("No remote configured, skipping branch localization")
            return
            
        try:
            remote = repo.remotes[self.remote]
            
            # Fetch to get latest remote refs
            callbacks = pygit2.RemoteCallbacks()
            callbacks.credentials = self._create_credentials_callback()
            
            l.debug(f"Fetching from remote {self.remote}")
            remote.fetch(callbacks=callbacks)
            
            # First, ensure the root branch exists locally if it exists remotely
            try:
                remote_root = repo.lookup_branch(f"{self.remote}/{BINSYNC_ROOT_BRANCH}", pygit2.GIT_BRANCH_REMOTE)
                local_root = repo.lookup_branch(BINSYNC_ROOT_BRANCH)
                
                if remote_root and remote_root.target and not local_root:
                    l.debug(f"Creating local root branch from remote")
                    remote_commit = repo[remote_root.target]
                    repo.create_branch(BINSYNC_ROOT_BRANCH, remote_commit)
                    l.debug(f"Created local root branch: {BINSYNC_ROOT_BRANCH}")
            except Exception as e:
                l.debug(f"Could not create root branch from remote: {e}")
            
            # Get all remote references using correct API
            remote_refs = remote.ls_remotes(callbacks=callbacks)
            
            for ref_info in remote_refs:
                ref_name = ref_info['name']
                ref_oid = ref_info['oid']
                
                l.debug(f"Found remote ref: {ref_name}")
                
                # Skip non-BinSync branches
                if f'{BINSYNC_BRANCH_PREFIX}/' not in ref_name:
                    continue
                    
                if "HEAD" in ref_name:
                    continue
                    
                # Extract local branch name from remote ref
                try:
                    # Handle refs like 'refs/heads/binsync/user1'
                    if ref_name.startswith('refs/heads/'):
                        local_name = ref_name[11:]  # Remove 'refs/heads/'
                    else:
                        continue
                        
                    l.debug(f"Processing remote branch: {ref_name} -> {local_name}")
                    
                    # Check if local branch already exists
                    existing_branch = repo.lookup_branch(local_name)
                    if existing_branch:
                        l.debug(f"Local branch {local_name} already exists, skipping creation")
                        continue
                        
                    # Create local tracking branch directly from remote commit
                    try:
                        if ref_oid:
                            remote_commit = repo[ref_oid]
                            new_branch = repo.create_branch(local_name, remote_commit)
                            l.info(f"Created local tracking branch: {local_name}")
                        else:
                            l.debug(f"Remote ref {ref_name} has no OID")
                    except (KeyError, AttributeError) as e:
                        l.debug(f"Failed to create local branch {local_name}: {e}")
                        
                except Exception as e:
                    l.debug(f"Error processing remote ref {ref_name}: {e}")
                    continue
                    
        except Exception as e:
            l.warning(f"Failed to localize remote branches: {e}")
            # Don't fail the entire initialization if remote branch localization fails
                
    @property
    def user_branch_name(self) -> str:
        return f"{BINSYNC_BRANCH_PREFIX}/{self.master_user}"
        
    @property
    def has_remote(self) -> bool:
        """Check if repository has a remote configured"""
        return self.repo and self.remote and self.remote in [r.name for r in self.repo.remotes]
        
    @property
    def last_push_ts(self):
        return self._last_push_time
        
    @property
    def last_pull_ts(self):
        return self._last_pull_time
        
    @property
    def last_commit_ts(self):
        return self._last_commit_time
        
    def users(self) -> List[User]:
        """Get list of all users from repository branches"""
        users = []
        
        for branch_name in self.repo.branches:
            if not branch_name.startswith(f"{BINSYNC_BRANCH_PREFIX}/"):
                continue
            if branch_name == BINSYNC_ROOT_BRANCH:
                continue
                
            try:
                # Extract username from branch name
                username = branch_name.split('/')[-1]
                
                branch = self.repo.lookup_branch(branch_name)
                if not branch or not branch.target:
                    l.debug(f"Branch {branch_name} has no target commit")
                    continue
                    
                commit = self.repo[branch.target]
                tree = commit.tree
                
                # Look for metadata.toml directly in the branch tree (no user subfolders)
                metadata = self._load_toml_from_tree(tree, "metadata.toml")
                if metadata:
                    user = User.from_metadata(metadata)
                    users.append(user)
                else:
                    # Create a basic user if no metadata found
                    user = User(username, "unknown")
                    users.append(user)
            except Exception as e:
                l.debug(f"Unable to load user from branch {branch_name}: {e}")
                continue
                
        return users
        
    def detect_repo_corruption(self) -> Dict[str, any]:
        """Detect various forms of repository corruption"""
        corruption_report = {
            "corrupted": False,
            "issues": [],
            "current_branch": None,
            "expected_branch": None,
            "filesystem_user": None,
            "expected_user": None
        }
        
        try:
            # Check current branch
            corruption_report["current_branch"] = self.repo.head.shorthand
            corruption_report["expected_branch"] = self.user_branch_name
            
            if corruption_report["current_branch"] != corruption_report["expected_branch"]:
                corruption_report["corrupted"] = True
                corruption_report["issues"].append(f"Wrong branch: on {corruption_report['current_branch']}, expected {corruption_report['expected_branch']}")
            
            # Check filesystem metadata
            metadata_path = pathlib.Path(self.repo_root) / "metadata.toml"
            if metadata_path.exists():
                try:
                    metadata = self._load_toml_from_tree(None, "metadata.toml")  # Read from filesystem
                    if metadata is None:
                        # Read directly from file
                        import toml
                        with open(metadata_path, 'r') as f:
                            metadata = toml.load(f)
                    
                    corruption_report["filesystem_user"] = metadata.get("user", "unknown")
                    corruption_report["expected_user"] = self.master_user
                    
                    if corruption_report["filesystem_user"] != corruption_report["expected_user"]:
                        corruption_report["corrupted"] = True
                        corruption_report["issues"].append(f"Wrong filesystem user: found {corruption_report['filesystem_user']}, expected {corruption_report['expected_user']}")
                        
                except Exception as e:
                    corruption_report["issues"].append(f"Failed to read metadata: {e}")
            
        except Exception as e:
            corruption_report["issues"].append(f"Failed to detect corruption: {e}")
        
        return corruption_report
        
    def _attempt_corruption_fix(self, corruption_report):
        """Attempt to automatically fix detected repository corruption"""
        try:
            # Fix wrong branch issue
            if "Wrong branch" in str(corruption_report["issues"]):
                l.info("Attempting to fix branch corruption...")
                master_branch = self.repo.lookup_branch(self.user_branch_name)
                if master_branch:
                    self._safe_checkout(master_branch, "corruption fix")
                    l.info(f"Fixed: Checked out to correct branch {self.user_branch_name}")
                    
            # Fix wrong filesystem user issue  
            if "Wrong filesystem user" in str(corruption_report["issues"]):
                l.info("Attempting to fix filesystem user corruption...")
                # Force a fresh state dump to overwrite corrupted metadata
                try:
                    from binsync.core.state import State
                    # Create a fresh state for the master user
                    fresh_state = State(self.master_user, client=self)
                    fresh_state.dump(pathlib.Path(self.repo_root))
                    l.info(f"Fixed: Reset filesystem metadata to correct user {self.master_user}")
                except Exception as e:
                    l.warning(f"Failed to fix filesystem user corruption: {e}")
                    
        except Exception as e:
            l.warning(f"Failed to fix corruption automatically: {e}")
    
    def _stash_conflicts_if_needed(self, operation_name: str = "checkout") -> bool:
        """
        Stash any conflicting changes before performing Git operations.
        This prevents "conflicts prevent checkout" errors during initialization.
        
        @param operation_name: Name of the operation being attempted (for logging)
        @return: True if conflicts were stashed, False if no conflicts
        """
        try:
            # Check if there are any uncommitted changes
            status = self.repo.status()
            if not status:
                return False  # No changes to stash
                
            # Check if we have a valid HEAD to stash against
            if not self.repo.head_is_unborn:
                try:
                    # Handle untracked files that might conflict
                    # First, check for untracked files and move them aside
                    untracked_backup_dir = None
                    for file_path, flags in status.items():
                        if flags & pygit2.GIT_STATUS_WT_NEW:  # Untracked file
                            if untracked_backup_dir is None:
                                untracked_backup_dir = pathlib.Path(self.repo_root) / ".binsync_untracked_backup"
                                untracked_backup_dir.mkdir(exist_ok=True)
                            
                            # Move untracked file to backup location
                            src_path = pathlib.Path(self.repo_root) / file_path
                            if src_path.exists():
                                backup_path = untracked_backup_dir / file_path
                                backup_path.parent.mkdir(parents=True, exist_ok=True)
                                src_path.rename(backup_path)
                    
                    if untracked_backup_dir:
                        l.warning(f"Moved untracked files to: {untracked_backup_dir}")
                    
                    # Now stash tracked changes (if any remain)
                    remaining_status = self.repo.status()
                    if remaining_status:
                        # Create a stash with current changes
                        signature = self._get_signature()
                        stash_msg = f"BinSync auto-stash before {operation_name} - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        
                        # Stash changes
                        stash_oid = self.repo.stash(signature, message=stash_msg)
                        
                        l.warning(f"Auto-stashed conflicting changes before {operation_name}")
                        l.warning(f"Stash message: '{stash_msg}'")
                        l.warning("You can recover these changes later using: git stash list && git stash apply")
                    
                    return True
                    
                except Exception as stash_error:
                    l.warning(f"Failed to stash changes before {operation_name}: {stash_error}")
                    
                    # As a last resort, try to reset hard to clean working directory
                    try:
                        if self.repo.head and self.repo.head.target:
                            head_commit = self.repo[self.repo.head.target]
                            self.repo.reset(head_commit.id, pygit2.GIT_RESET_HARD)
                            l.warning(f"Performed hard reset to clean working directory for {operation_name}")
                            l.warning("WARNING: Uncommitted changes were discarded!")
                            return True
                    except Exception as reset_error:
                        l.error(f"Failed to clean working directory: {reset_error}")
                        
            return False
            
        except Exception as e:
            l.warning(f"Error checking for conflicts before {operation_name}: {e}")
            return False
    
    def _safe_checkout(self, branch, operation_name: str = "checkout"):
        """
        Safely checkout a branch, automatically stashing conflicts if needed.
        
        @param branch: Branch object to checkout
        @param operation_name: Name of operation for logging
        """
        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                self.repo.checkout(branch)
                return  # Success!
                
            except Exception as e:
                error_msg = str(e).lower()
                if "conflict" in error_msg and attempt == 0:
                    # First attempt failed due to conflicts - try stashing
                    l.info(f"Checkout blocked by conflicts, attempting to stash...")
                    stashed = self._stash_conflicts_if_needed(operation_name)
                    if stashed:
                        continue  # Try checkout again
                        
                # Re-raise the error if we couldn't resolve it
                raise
        
    def refresh_remote_users(self):
        """Force refresh of remote users by localizing remote branches"""
        if self.has_remote:
            try:
                self._localize_remote_branches(self.repo)
                l.info("Refreshed remote users - new users should now be visible")
            except Exception as e:
                l.warning(f"Failed to refresh remote users: {e}")
        else:
            l.debug("No remote configured, cannot refresh remote users")
        
    def get_state(self, user: Optional[str] = None, commit_hash: Optional[str] = None) -> State:
        """Get state for a specific user"""
        if user is None:
            user = self.master_user
            
        return self._parse_state_from_commit(user=user, commit_hash=commit_hash, is_master=(user == self.master_user))
        
    def _parse_state_from_commit(self, user: Optional[str] = None, commit_hash: Optional[str] = None, is_master: bool = False) -> State:
        """Parse state from a specific commit or user branch"""
        if user is None and commit_hash is None:
            raise ValueError("Must specify either a user or a commit hash")
            
        state = State(None)
        try:
            if commit_hash:
                commit = self.repo[commit_hash]
                tree = commit.tree
            else:
                branch = self.repo.lookup_branch(f"{BINSYNC_BRANCH_PREFIX}/{user}")
                if branch is None or not branch.target:
                    if is_master:
                        return State(user, client=self)
                    else:
                        return State(user)
                commit = self.repo[branch.target]
                tree = commit.tree
                
            # For master user, use filesystem if available (since we're checked out to their branch)
            if is_master:
                # Read directly from repo root - no user subfolder!
                repo_path = pathlib.Path(self.repo_root)
                if repo_path.exists():
                    state = State.parse(repo_path, client=self)
                    # CRITICAL: Ensure the state has the correct user!
                    if state.user != user:
                        l.warning(f"State corruption detected! Expected user {user}, got {state.user}. Fixing...")
                        state.user = user
                    return state
            
            # For non-master users, read directly from Git objects (no checkout needed!)
            state = self._parse_state_from_tree(tree, user, is_master)
            
        except MetadataNotFoundError:
            if is_master:
                state = State(user, client=self)
        except Exception as e:
            if is_master:
                raise
            else:
                l.critical(f"Invalid state for {user}, dropping: {e}")
                state = State(user)
                
        return state
        
    def _parse_state_from_tree(self, tree, user: str, is_master: bool = False) -> State:
        """Parse state directly from a Git tree object without filesystem checkout"""
        try:
            # The tree should contain artifacts directly (functions/, comments.toml, etc.)
            # No user subfolders - each branch IS the user's data
            
            # Create temporary directory to extract the tree contents for State.parse
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract all files from the tree directly to temp directory
                self._extract_tree_to_filesystem(tree, temp_path)
                
                # Now we can use State.parse on the extracted files
                state = State.parse(temp_path, client=self if is_master else None)
                # CRITICAL: Ensure the state has the correct user!
                if state.user != user:
                    l.warning(f"State corruption detected! Expected user {user}, got {state.user}. Fixing...")
                    state.user = user
                return state
                
        except Exception as e:
            l.debug(f"Failed to parse state from tree for {user}: {e}")
            return State(user, client=self if is_master else None)
    
    def _extract_tree_to_filesystem(self, tree, target_path: Path):
        """Recursively extract a Git tree to filesystem"""
        for entry in tree:
            entry_path = target_path / entry.name
            
            if entry.type == pygit2.GIT_OBJECT_TREE:
                # It's a directory - create it and recurse
                entry_path.mkdir(exist_ok=True)
                subtree = self.repo[entry.id]
                self._extract_tree_to_filesystem(subtree, entry_path)
            elif entry.type == pygit2.GIT_OBJECT_BLOB:
                # It's a file - write the blob content
                blob = self.repo[entry.id]
                with open(entry_path, 'wb') as f:
                    f.write(blob.data)
        
    def commit_state(self, state: State, commit_msg: Optional[str] = None) -> bool:
        """Commit state changes to repository"""
        if self.master_user != state.user:
            raise ExternalUserCommitError(f"User {self.master_user} is not allowed to commit to user {state.user}")
            
        commit_msg = commit_msg or "Generic BS Commit"
        
        # Checkout to master user branch
        self._checkout_to_master_user()
        
        # CRITICAL: Validate we're on the right branch before proceeding
        try:
            current_branch = self.repo.head.shorthand
            expected_branch = self.user_branch_name
            if current_branch != expected_branch:
                l.error(f"Branch corruption detected! On {current_branch}, expected {expected_branch}")
                # Force checkout to correct branch
                master_branch = self.repo.lookup_branch(self.user_branch_name)
                if master_branch:
                    self._safe_checkout(master_branch, "commit state validation")
                    l.info(f"Forced checkout to correct branch: {self.user_branch_name}")
                else:
                    raise Exception(f"Master user branch {self.user_branch_name} not found!")
        except Exception as e:
            l.error(f"Failed to validate branch state: {e}")
            raise
        
        # Dump state to filesystem directly in repo root (no user subfolder!)
        # Each user branch should contain artifacts directly, not in user subfolders
        state.dump(pathlib.Path(self.repo_root))
        
        # Add changes to index - add all files in repo root (excluding .git)
        repo_root_path = pathlib.Path(self.repo_root)
        for root, dirs, files in os.walk(repo_root_path):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            for file in files:
                file_path = pathlib.Path(root) / file
                rel_path = file_path.relative_to(repo_root_path)
                self.repo.index.add(str(rel_path))
        self.repo.index.write()
        
        # Check if there are changes to commit
        tree_id = self.repo.index.write_tree()
        parent = None
        try:
            if self.repo.head and self.repo.head.target:
                parent = self.repo.head.target
                parent_tree = self.repo[parent].tree
                if parent_tree.id == tree_id:
                    return False  # No changes to commit
        except (pygit2.GitError, AttributeError) as e:
            l.debug(f"No parent commit or head: {e}")
            pass  # No parent commit
            
        # Create commit
        signature = self._get_signature()
        parents = [parent] if parent else []
        
        commit_id = self.repo.create_commit(
            "HEAD",
            signature,
            signature,
            commit_msg,
            tree_id,
            parents
        )
        
        self._last_commit_time = datetime.datetime.now(tz=datetime.timezone.utc)
        state._dirty = False
        return True
        
    def pull(self) -> bool:
        """Pull changes from remote repository"""
        if not self.has_remote:
            return False
            
        self.last_pull_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        
        try:
            remote = self.repo.remotes[self.remote]
            callbacks = pygit2.RemoteCallbacks()
            callbacks.credentials = self._create_credentials_callback()
                
            remote.fetch(callbacks=callbacks)
            
            # Update root branch without checkout (we don't need to checkout root branch)
            root_branch = self.repo.lookup_branch(BINSYNC_ROOT_BRANCH)
            remote_root = self.repo.lookup_branch(f"{self.remote}/{BINSYNC_ROOT_BRANCH}", pygit2.GIT_BRANCH_REMOTE)
            
            if root_branch and root_branch.target:
                # Fast-forward merge if possible (no checkout needed)
                if remote_root and remote_root.target:
                    root_branch.set_target(remote_root.target)
                    l.debug(f"Updated root branch from remote")
                else:
                    l.debug(f"Remote root branch {self.remote}/{BINSYNC_ROOT_BRANCH} not found or has no target")
            elif remote_root and remote_root.target:
                # Create local root branch from remote (no checkout needed)
                try:
                    remote_commit = self.repo[remote_root.target]
                    new_root_branch = self.repo.create_branch(BINSYNC_ROOT_BRANCH, remote_commit)
                    l.info(f"Created local root branch from remote: {BINSYNC_ROOT_BRANCH}")
                except Exception as e:
                    l.warning(f"Failed to create root branch from remote: {e}")
            else:
                l.debug(f"Root branch {BINSYNC_ROOT_BRANCH} not found locally or remotely")
                
            self._last_pull_time = datetime.datetime.now(tz=datetime.timezone.utc)
            self.active_remote = True
            
            # Merge other branches
            self._merge_branches()
            
            # Update local tracking branches after pull
            self._localize_remote_branches(self.repo)
            
            # Ensure we're checked out to the master user's branch
            try:
                master_branch = self.repo.lookup_branch(self.user_branch_name)
                if master_branch and self.repo.head.shorthand != self.user_branch_name.split('/')[-1]:
                    self._safe_checkout(master_branch, "pull operation")
                    l.debug(f"Ensured checkout to master user branch: {self.user_branch_name}")
            except Exception as e:
                l.debug(f"Failed to ensure master user branch checkout: {e}")
            
            return True
            
        except Exception as e:
            self._handle_auth_error(e, "pull")
            self.active_remote = False
            return False
            
    def push(self) -> bool:
        """Push changes to remote repository"""
        if not self.has_remote:
            return False
            
        self.last_push_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        
        try:
            remote = self.repo.remotes[self.remote]
            callbacks = pygit2.RemoteCallbacks()
            callbacks.credentials = self._create_credentials_callback()
                
            # Push root branch and user branch
            refs_to_push = []
            
            # Only push root branch if it exists and has commits
            root_branch = self.repo.lookup_branch(BINSYNC_ROOT_BRANCH)
            if root_branch and root_branch.target:
                try:
                    # Verify the commit exists
                    commit = self.repo[root_branch.target]
                    refs_to_push.append(f"refs/heads/{BINSYNC_ROOT_BRANCH}")
                    l.debug(f"Root branch {BINSYNC_ROOT_BRANCH} ready to push")
                except KeyError:
                    l.warning(f"Root branch {BINSYNC_ROOT_BRANCH} target commit not found")
            else:
                l.debug(f"Root branch {BINSYNC_ROOT_BRANCH} not found or has no target")
                
            # Only push user branch if it exists and has commits
            user_branch = self.repo.lookup_branch(self.user_branch_name)
            if user_branch and user_branch.target:
                try:
                    # Verify the commit exists
                    commit = self.repo[user_branch.target]
                    refs_to_push.append(f"refs/heads/{self.user_branch_name}")
                    l.debug(f"User branch {self.user_branch_name} ready to push")
                except KeyError:
                    l.warning(f"User branch {self.user_branch_name} target commit not found")
            else:
                l.debug(f"User branch {self.user_branch_name} not found or has no target")
                
            if refs_to_push:
                remote.push(refs_to_push, callbacks=callbacks)
                l.debug(f"Successfully pushed branches: {refs_to_push}")
            else:
                l.warning("No valid branches to push")
            
            self._last_push_time = datetime.datetime.now(tz=datetime.timezone.utc)
            self.active_remote = True
            return True
            
        except Exception as e:
            self._handle_auth_error(e, "push")
            self.active_remote = False
            return False
            
    def _checkout_to_master_user(self):
        """Checkout to master user branch"""
        branch = self.repo.lookup_branch(self.user_branch_name)
        if not branch:
            raise Exception(f"Master user branch {self.user_branch_name} not found")
        self._safe_checkout(branch, "master user checkout")
        
    def _merge_branches(self):
        """Merge remote changes into local branches"""
        current_branch = None
        try:
            # Remember current branch so we can restore it
            current_branch = self.repo.head.shorthand if self.repo.head else None
        except:
            pass
            
        for branch_name in self.repo.branches:
            if "HEAD" in branch_name or not branch_name.startswith(BINSYNC_BRANCH_PREFIX):
                continue
                
            try:
                branch = self.repo.lookup_branch(branch_name)
                remote_branch = self.repo.lookup_branch(f"{self.remote}/{branch_name}", pygit2.GIT_BRANCH_REMOTE)
                
                if remote_branch and remote_branch.target and branch and branch.target:
                    # Only checkout if this is the master user's branch
                    if branch_name == self.user_branch_name:
                        self._safe_checkout(branch, "branch merge")
                    
                    # Simple fast-forward merge (no checkout needed for the merge operation itself)
                    try:
                        branch.set_target(remote_branch.target)
                        l.debug(f"Merged remote changes for branch: {branch_name}")
                    except Exception as merge_error:
                        l.debug(f"Failed to merge branch {branch_name}: {merge_error}")
                else:
                    l.debug(f"Skipping merge for {branch_name}: remote_branch={remote_branch}, branch={branch}")
            except Exception as e:
                l.debug(f"Failed to merge branch {branch_name}: {e}")
                
        # Restore to master user branch if we're not already there
        try:
            if current_branch != self.user_branch_name.split('/')[-1]:  # Get just the branch name part
                master_branch = self.repo.lookup_branch(self.user_branch_name)
                if master_branch:
                    self._safe_checkout(master_branch, "restore master branch")
        except Exception as e:
            l.debug(f"Failed to restore to master user branch: {e}")
                
    def _get_stored_hash(self, repo: pygit2.Repository) -> str:
        """Get the stored binary hash from root branch"""
        try:
            root_branch = repo.lookup_branch(BINSYNC_ROOT_BRANCH)
            if not root_branch or not root_branch.target:
                l.debug(f"Root branch {BINSYNC_ROOT_BRANCH} not found or has no target")
                return ""
            commit = repo[root_branch.target]
            tree = commit.tree
            hash_blob = tree["binary_hash"]
            return repo[hash_blob.id].data.decode().strip()
        except (KeyError, AttributeError) as e:
            l.debug(f"Could not get stored hash: {e}")
            return ""
            
    def _load_toml_from_tree(self, tree, filename: str) -> Optional[dict]:
        """Load TOML data from a tree object"""
        try:
            blob = tree[filename]
            content = self.repo[blob.id].data.decode()
            return toml.loads(content)
        except KeyError:
            return None
        except Exception as e:
            l.debug(f"Error loading TOML from {filename}: {e}")
            return None
            
    def find_commits_before_ts(self, ts: int, users: List[str]) -> Dict[str, str]:
        """Find commits for users before a specific timestamp"""
        best_commits = {}
        
        for user in users:
            try:
                branch = self.repo.lookup_branch(f"{BINSYNC_BRANCH_PREFIX}/{user}")
                if not branch:
                    continue
                    
                walker = self.repo.walk(branch.target, pygit2.GIT_SORT_TIME | pygit2.GIT_SORT_REVERSE)
                for commit in walker:
                    if commit.commit_time <= ts:
                        best_commits[user] = commit.hex
                        break
            except Exception as e:
                l.debug(f"Error finding commits for user {user}: {e}")
                
        return best_commits
        
    def shutdown(self):
        """Clean up resources"""
        if hasattr(self, 'repo') and self.repo:
            # pygit2 repositories don't need explicit closing
            pass
            
        if self.repo_lock is not None:
            self.repo_lock.release()
            if self._repo_lock_path.exists():
                self._repo_lock_path.unlink(missing_ok=True)
                
    @staticmethod
    def add_data(index, path: str, data: bytes):
        """Add data to index (for compatibility with existing code)"""
        fullpath = os.path.join(os.path.dirname(index.path), path)
        pathlib.Path(fullpath).parent.mkdir(parents=True, exist_ok=True)
        with open(fullpath, 'wb') as fp:
            fp.write(data)
        index.add(path)
        
    @staticmethod
    def remove_data(index, path: str):
        """Remove data from index (for compatibility with existing code)"""
        fullpath = os.path.join(os.path.dirname(index.path), path)
        if os.path.exists(fullpath):
            os.remove(fullpath)
        try:
            index.remove(path)
        except KeyError:
            pass  # File wasn't in index
            
    @staticmethod
    def load_file_from_tree(tree, filename: str) -> Optional[str]:
        """Load file content from tree object"""
        try:
            blob = tree[filename]
            return blob.data.decode()
        except (KeyError, UnicodeDecodeError):
            return None