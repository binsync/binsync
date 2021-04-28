
# binsync

## What is binsync

Binsync enables manual and automated synchronization of the following reverse engineering artifacts between IDA Pro, Binary Ninja, and angr management running on the same machine or different machines:

- Function names
- Comments
- Names of stack variables
- Types of stack variables (warning!)
- User-defined structs

All data is stored in a human-friendly text format (toml) inside a Git repo.


## Installing

First install [Binsync Core](#binsync-core), then install the plugin associate to your decompiler of choice

### Binsync Core

While in the root of this GitHub repo run:
```bash
python3 -m pip install --user .
```

Or any modifications for custom enviornments.

### IDA Pro
After cloning down this repo, simply copy the `ida_binsync` folder and python file into your IDA Pro plugins folder.
```bash
cp -r binsync/plugins/ida_binsync/* IDA_HOME/plugins/
```
For me `IDA_HOME=~/ida/ida-7.5sp2-py38`; it may be different for you. 

### angr management
`binsync` is built into angr management. To use it, just activate the plugin by going to the plugins tab and
selecting `binsync`, then configuring it. 

## Usage

Follow the user story described in the [Wiki](https://github.com/angr/binsync/wiki).

## TODO
### Binsync Core
- Make new users a new branch.
- Gather real update times for repos

### IDA Integration
- Fix Stack Variable Syncing
- Attempt to do a context click on functions like in angr-management
- Fix comments for locations 

