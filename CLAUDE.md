# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BinSync is a decompiler collaboration tool built on Git versioning that enables fine-grained reverse engineering collaboration across different decompilers (IDA Pro, Binary Ninja, Ghidra, angr-management). It synchronizes Reverse Engineering Artifacts (REAs) like function headers, stack variables, structs, enums, and comments between team members.

## Architecture

### Core Components

- **Controller (`binsync/controller.py`)**: Main orchestration class that manages the interaction between UI, client, and state
- **Client (`binsync/core/client.py`)**: Handles Git operations, branch management, and remote synchronization
- **State (`binsync/core/state.py`)**: Manages local artifact state and serialization/deserialization to TOML format
- **Scheduler (`binsync/core/scheduler.py`)**: Background task scheduler for auto-sync operations
- **Cache (`binsync/core/cache.py`)**: Artifact caching system for performance optimization

### Decompiler Integration

- **Interface Overrides (`binsync/interface_overrides/`)**: Decompiler-specific implementations extending libbs DecompilerInterface
- **Plugin System**: Main plugin creation through `create_plugin()` in `__init__.py`
- **UI Components (`binsync/ui/`)**: Cross-platform UI panels and dialogs

### Key Dependencies

- **libbs**: Core binary analysis library for decompiler abstraction (>=2.15.6)
- **GitPython**: Git operations and repository management
- **PySide6**: GUI framework (for Ghidra support)

## Development Commands

### Installation & Setup
```bash
# Standard installation
pip3 install binsync && binsync --install

# Development installation (requires pip>=23.0.0)
pip3 install -e .

# With Ghidra support
pip3 install binsync[ghidra]

# With extra features
pip3 install binsync[extras]
```

### Testing
```bash
# Run all tests
pytest

# Test location
cd tests/
```

### Dependencies
- Python >=3.10 required
- Git must be installed on system
- Individual decompiler version requirements vary (see README.md)

## Key Patterns

### Artifact Management
- All artifacts inherit from libbs `Artifact` base class
- State management uses TOML serialization with hex encoding for addresses
- Branch-based isolation: each user gets their own Git branch (`binsync/username`)

### Git Integration
- Uses `BINSYNC_ROOT_BRANCH = 'binsync/__root__'` for shared state
- Individual user branches follow pattern `binsync/username`
- Background sync through scheduler system

### UI Architecture
- Control panel as main interface hub
- Table-based views for different artifact types
- Progress tracking with dedicated progress window
- Force push dialogs for conflict resolution

### Error Handling
- Custom exceptions in `binsync/core/errors.py`
- Decorator-based state checking (`@init_checker`, `@fill_event`)
- Comprehensive logging through custom logger configuration

## Testing

Manual testing procedures are documented in `tests/testing_guide.md`. Key test scenarios:
- Cross-user synchronization workflows
- Non-standard write orders and edge cases
- README example verification with fauxware binary

## Version Management

Version is defined in `binsync/__init__.py` and must be synchronized with `binsync/stub_files/plugin.json`.