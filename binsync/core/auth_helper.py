#!/usr/bin/env python3
"""
Authentication helper for BinSync Git operations.

This module provides utilities to help users diagnose and fix Git authentication issues
across different platforms (macOS, Windows, Linux).
"""

import logging
import subprocess
import platform
from pathlib import Path
from typing import Dict, List, Optional

l = logging.getLogger(__name__)


class GitAuthHelper:
    """Helper class for Git authentication diagnostics and setup"""
    
    @staticmethod
    def diagnose_auth_issues() -> Dict[str, any]:
        """
        Diagnose potential Git authentication issues and provide recommendations.
        
        Returns:
            Dict containing authentication status and recommendations
        """
        diagnosis = {
            "platform": platform.system(),
            "ssh_keys": GitAuthHelper._check_ssh_keys(),
            "ssh_agent": GitAuthHelper._check_ssh_agent(),
            "git_config": GitAuthHelper._check_git_config(),
            "credential_helper": GitAuthHelper._check_credential_helper(),
            "recommendations": []
        }
        
        # Generate platform-specific recommendations
        diagnosis["recommendations"] = GitAuthHelper._generate_recommendations(diagnosis)
        
        return diagnosis
    
    @staticmethod
    def _check_ssh_keys() -> Dict[str, any]:
        """Check for SSH keys in common locations"""
        home = Path.home()
        ssh_dir = home / ".ssh"
        
        key_info = {
            "ssh_directory_exists": ssh_dir.exists(),
            "keys_found": [],
            "total_keys": 0
        }
        
        if not ssh_dir.exists():
            return key_info
            
        # Common SSH key types
        key_types = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]
        
        for key_type in key_types:
            private_key = ssh_dir / key_type
            public_key = ssh_dir / f"{key_type}.pub"
            
            if private_key.exists():
                key_info["keys_found"].append({
                    "name": key_type,
                    "private_key": str(private_key),
                    "public_key": str(public_key) if public_key.exists() else None,
                    "has_public_key": public_key.exists(),
                    "permissions": oct(private_key.stat().st_mode)[-3:] if private_key.exists() else None
                })
                key_info["total_keys"] += 1
                
        return key_info
    
    @staticmethod 
    def _check_ssh_agent() -> Dict[str, any]:
        """Check SSH agent status"""
        agent_info = {
            "running": False,
            "loaded_keys": [],
            "ssh_auth_sock": None,
            "ssh_agent_pid": None
        }
        
        # Check environment variables
        import os
        agent_info["ssh_auth_sock"] = os.environ.get("SSH_AUTH_SOCK")
        agent_info["ssh_agent_pid"] = os.environ.get("SSH_AGENT_PID")
        
        try:
            # Try to list loaded keys
            result = subprocess.run(
                ["ssh-add", "-l"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode == 0:
                agent_info["running"] = True
                # Parse loaded keys
                for line in result.stdout.strip().split('\\n'):
                    if line.strip():
                        agent_info["loaded_keys"].append(line.strip())
            elif result.returncode == 1:
                # Agent running but no keys loaded
                agent_info["running"] = True
                
        except Exception as e:
            l.debug(f"Error checking SSH agent: {e}")
            
        return agent_info
    
    @staticmethod
    def _check_git_config() -> Dict[str, any]:
        """Check Git configuration"""
        config_info = {
            "user_name": None,
            "user_email": None,
            "credential_helper": None,
            "ssh_command": None
        }
        
        git_configs = [
            ("user.name", "user_name"),
            ("user.email", "user_email"), 
            ("credential.helper", "credential_helper"),
            ("core.sshCommand", "ssh_command")
        ]
        
        for git_key, info_key in git_configs:
            try:
                result = subprocess.run(
                    ["git", "config", "--global", git_key],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    config_info[info_key] = result.stdout.strip()
            except Exception as e:
                l.debug(f"Error checking git config {git_key}: {e}")
                
        return config_info
    
    @staticmethod
    def _check_credential_helper() -> Dict[str, any]:
        """Check credential helper configuration"""
        helper_info = {
            "configured": False,
            "helper_type": None,
            "available_helpers": []
        }
        
        # Check if credential helper is configured
        try:
            result = subprocess.run(
                ["git", "config", "--global", "credential.helper"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                helper_info["configured"] = True
                helper_info["helper_type"] = result.stdout.strip()
        except Exception:
            pass
            
        # Check available credential helpers
        common_helpers = ["store", "cache", "manager", "osxkeychain", "wincred"]
        for helper in common_helpers:
            try:
                result = subprocess.run(
                    ["git", "credential-" + helper],
                    capture_output=True,
                    timeout=5
                )
                # If command exists (even if it fails), it's available
                helper_info["available_helpers"].append(helper)
            except Exception:
                pass
                
        return helper_info
    
    @staticmethod
    def _generate_recommendations(diagnosis: Dict[str, any]) -> List[str]:
        """Generate platform-specific recommendations"""
        recommendations = []
        platform_name = diagnosis["platform"]
        
        # SSH key recommendations
        if diagnosis["ssh_keys"]["total_keys"] == 0:
            if platform_name == "Windows":
                recommendations.extend([
                    "Generate an SSH key (in Git Bash or PowerShell):",
                    "  ssh-keygen -t ed25519 -C 'your-email@example.com'",
                    "Add the public key to your Git provider (GitHub/GitLab):"
                ])
            else:
                recommendations.extend([
                    "Generate an SSH key:",
                    "  ssh-keygen -t ed25519 -C 'your-email@example.com'",
                    "Add the public key to your Git provider (GitHub/GitLab):"
                ])
        
        # SSH agent recommendations
        if diagnosis["ssh_keys"]["total_keys"] > 0 and not diagnosis["ssh_agent"]["running"]:
            if platform_name == "Darwin":  # macOS
                recommendations.extend([
                    "Start SSH agent and add your key:",
                    "  ssh-add --apple-use-keychain ~/.ssh/id_ed25519",
                    "Configure SSH to use keychain:",
                    "  echo 'Host *\\n  AddKeysToAgent yes\\n  UseKeychain yes' >> ~/.ssh/config"
                ])
            elif platform_name == "Windows":
                recommendations.extend([
                    "Start SSH agent (in Git Bash):",
                    "  eval $(ssh-agent -s)",
                    "  ssh-add ~/.ssh/id_ed25519",
                    "Or use Windows SSH agent service"
                ])
            else:  # Linux
                recommendations.extend([
                    "Start SSH agent and add your key:",
                    "  eval $(ssh-agent -s)",
                    "  ssh-add ~/.ssh/id_ed25519",
                    "Add to shell profile to persist across sessions"
                ])
        
        # Credential helper recommendations
        if not diagnosis["credential_helper"]["configured"]:
            if platform_name == "Darwin":  # macOS
                recommendations.append("Set up credential helper: git config --global credential.helper osxkeychain")
            elif platform_name == "Windows":
                recommendations.append("Set up credential helper: git config --global credential.helper manager")
            else:  # Linux
                recommendations.append("Set up credential helper: git config --global credential.helper store")
        
        # Git config recommendations
        if not diagnosis["git_config"]["user_name"] or not diagnosis["git_config"]["user_email"]:
            recommendations.extend([
                "Configure Git user information:",
                "  git config --global user.name 'Your Name'",
                "  git config --global user.email 'your-email@example.com'"
            ])
        
        return recommendations
    
    @staticmethod
    def print_diagnosis():
        """Print a comprehensive authentication diagnosis"""
        diagnosis = GitAuthHelper.diagnose_auth_issues()
        
        print("🔐 BinSync Git Authentication Diagnosis")
        print("=" * 50)
        print(f"Platform: {diagnosis['platform']}")
        print()
        
        # SSH Keys
        print("📁 SSH Keys:")
        if diagnosis["ssh_keys"]["total_keys"] > 0:
            for key in diagnosis["ssh_keys"]["keys_found"]:
                status = "✅" if key["has_public_key"] else "⚠️"
                print(f"  {status} {key['name']} - {key['private_key']}")
                if not key["has_public_key"]:
                    print(f"    Missing public key: {key['private_key']}.pub")
        else:
            print("  ❌ No SSH keys found")
        print()
        
        # SSH Agent
        print("🔑 SSH Agent:")
        if diagnosis["ssh_agent"]["running"]:
            print("  ✅ SSH agent is running")
            if diagnosis["ssh_agent"]["loaded_keys"]:
                print("  Loaded keys:")
                for key in diagnosis["ssh_agent"]["loaded_keys"]:
                    print(f"    • {key}")
            else:
                print("  ⚠️ No keys loaded in agent")
        else:
            print("  ❌ SSH agent not running")
        print()
        
        # Git Config
        print("⚙️ Git Configuration:")
        config = diagnosis["git_config"]
        print(f"  User name: {config['user_name'] or '❌ Not set'}")
        print(f"  User email: {config['user_email'] or '❌ Not set'}")
        print(f"  Credential helper: {config['credential_helper'] or '❌ Not set'}")
        print()
        
        # Recommendations
        if diagnosis["recommendations"]:
            print("💡 Recommendations:")
            for rec in diagnosis["recommendations"]:
                if rec.startswith("  "):
                    print(f"  {rec}")
                else:
                    print(f"  • {rec}")
            print()
        else:
            print("✅ Authentication looks properly configured!")


if __name__ == "__main__":
    GitAuthHelper.print_diagnosis()