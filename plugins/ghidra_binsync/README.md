# Ghidra Plugin
## How it works
Currently the Ghidra plugin is just a Java UI that starts a python process that runs as a server. The java 
portion then sends GET/POST requests to request BinSync to change current active user of the repo. You
can think of this as a API to doing a `git checkout <user>` so that the Java side can now just read that file.

## Installing
This is going to be scuffed, hold on to your boots.

### Setup BinSync Core
From the root of the `binsync` repo, pip install this code. Note, if you are reading this, you must be on the
correct branch for Ghidra support. Thus, no checkout is needed. 
```bash
(cd ../../ && python3 -m pip install --user -e .)
```

### Setup Ghidra
Second, copy the `ghidraScripts.java` code into the correct `ghidra_scripts` folder:
```bash
cp ./ghidraScripts.java ~/ghidra_scripts/
```

### Setup a Sync Repo
Third, you are going to need a repo for which you sync changes. Here is a good one: [sync_test](https://github.com/mahaloz/sync_test).
Clone down that repo with ssh, probably in your `~/`:
```bash
git clone git@github.com:mahaloz/sync_test.git
```

Now, its important that you make sure that you have the ability to push and pull to this repo with your
given SSH key. If it does not work, make a new non-password protected key and add it to GitHub, then try again.

### Putting it all together
Finally, you are going to want to edit the `ghidraScripts.java` for the correct config. Right now,
the config is on line `201`, it looks like this by default:
```java
// ---- PUT CONFIG HERE ---- //
public String syncRepoPath = "/Users/mahaloz/binsync/sync_test";
public String syncServerPath = "/Users/mahaloz/github/binsync/plugins/ghidra_binsync/binsync_server.py";
public String masterUser = "headless_0"
```

1. For `masterUser`, keep it `headless_0`, as it does not matter the username. 
2. For `syncServerPath`, give it the **absolute path** of the location of the `binsync_server.py`.
3. For `syncRepoPath`, give is the **absoulute path** of the location of the Sync Repo you pulled earlier. 

## Usage
Now that you are all setup, finally launch Ghidra. If you are testing it, use the `fauxware` binary that
is in the same folder as this readme. It is the same binary used the example Sync Repo. 

Start the plugin script and a popup should happen with a table UI. It should have all the names of all the
branches found in the earlier Sync Repo. If you pull, the local repo should change its user. 

Good luck!