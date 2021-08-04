
# BinSync

## What is BinSync

BinSync enables manual and automated synchronization of the following reverse engineering artifacts between IDA Pro, Binary Ninja, and angr management running on the same machine or different machines:

- Function names
- Comments
- Names & types of stack variables
- User-defined structs

All data is stored in a human-friendly text format (toml) inside a Git repo.

## Supported Platforms
Currently we support the following decompilers:
- angr-management: **latest release**
- IDA Pro: **>= 7.4**

Binary Ninja is partially supported, but lacks modern UI updates. 
Currently, we have no implementation for Ghidra, but we are looking into a solution.

## Installing

### Git Prereqs

BinSync's backbone is `git`, which means to use BinSync you must have two things:
1. `git` must be installed on your system.
2. You must use an ssh key to pull and push, AND **it must be password unlocked**.

Number 2 is very important. Many users have complained about BinSync not auto pushing/pulling
things with git and almost all of them did not have their ssh key unlocked. If your key requires you 
to enter a password, you have two options:

1. pull some private repo once so you need to enter your password and unlock the key
2. generate a new key that is not password protected and add it to GitHub (or whatever host you use)


### Install Script 
To install just run the install script from the root of the repo and define the needed enviornment
variable for the type of install you are doing. If you are installing for IDA Pro, you must define the variable
`IDA_HOME`, which should be home folder of your IDA install. For me it looks like this:

```bash
IDA_HOME=~/ida/ida-7.6 ./scripts/install.sh
```

## Usage  
### Verifying your download works (IDA)

~Follow this simple verification for IDA: [Here]()~

TODO:
1. make a `~/sync_repos` folder
2. clone mahaloz repo: `git clone git@github.com:mahaloz/sync_test.git`
3. open up ida
4. `Ctrl+Shift+B` to open config
5. put the folder location as `~/sync_repos/sync_test`
6. pull something

### Setting up a Sync Repo for a challenge for the first time

1. Create a repo for a challenge on GitHub, and clone it down
```bash
git clone git_repo 
cd git_repo
```
2. Create a `root` branch for BinSync, and push it
```bash
git checkout -b binsync/__root__
git push --set-upstream origin binsync/__root__
```
3. Add the md5 hash of the binary for tracking, and push it
```bash
md5sum the_target_binary_you_care_about | awk '{ print $1 }' > binary_hash
git add binary_hash
git commit -m "added binary hash"
git push
```

Alternatively, you can use the script `setup_repo_for_binsync.sh` in the `scripts` folder that will do 
steps 2 and 3 given the repo and the binary. Its less verbose though:

```bash
./scripts/setup_repo_for_binsync.sh /path/to/repo /path/to/binary
```

Follow the earlier story to verify you can connect in IDA [here]().

## Known Bugs
Fixing any bug will require an IDA restart usually.

### Git Error 1
You get a python crash that looks something like this:
```python
# [truncated]
    self.tree = Tree(self.repo, hex_to_bin(readline().split()[1]), Tree.tree_id << 12, '')
binascii.Error: Non-hexadecimal digit found
```

#### FIX:
Restart IDA and reconnect to that same user.