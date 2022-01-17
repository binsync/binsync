
# BinSync

<p align="center">
   <img src="https://i.imgur.com/zQcqqML.png" alt="logo"/>
</p>

BinSync is a decompiler collaboration tool built on the Git versioning system to enable fined grained reverse
engineering collaboration regardless of decompiler. 

All good decompilers share common objects called Reverse Engineering Artifacts (REAs). These REAs are the 
center of BinSync's syncing ability. Here are the supported REAs:
- Function headers (symbol, args, type)
- Stack Variables (symbol, type)
- Structs   
- Comments

Note: all types support user-created types like structs.

[![Discord](https://img.shields.io/discord/900841083532087347?label=Discord&style=plastic)](https://discord.gg/wZSCeXnEvR)

## Supported Platforms
- IDA Pro: **>= 7.3**
- Binary Ninja: **>= 2.4**
- angr-management: **>= 9.0**

All versions require **Python >= 3.4** and **Git** installed on your system.

## Installing
### Script (Fast)
Use the installation script provided in the repo:
```bash
./install.sh --ida /path/to/ida/plugins
```

Use `--help`, for more information.

### Manual 
If you are unable to install BinSync with the script above, you are probably on Windows. In that case, installing
BinSync is a two-step process. 
1. Install the core with the Python version associated with your decompiler: `pip3 install -e .`
2. Install the decompiler plugin directly into your decompilers `plugin` folder.

For step 2, you copy all files (and folders) found under the plugin folder in BinSync. An an example, for IDA, 
you would copy everything in `plugins/ida_binsync/*` to the plugins folder.


## Usage
Although BinSync supports various decompilers, which may have not so subtle differences, a lot of the way you interact
with BinSync is standard across all versions. In each decompiler we use the same UI regardless of QT version. 

For decompiler specific intricacies, please see our supported decompilers usage manual in our Wiki.
If you are using Binja, see our extra install steps.

### Validation
1. Copy down a local version of the testing repo and grab the `fauxware` binary
```bash 
git clone git@github.com:mahaloz/binsync_example_repo.git
cp binsync_example_repo/fauxware .
```

2. Open the fauxware binary in your decompiler, verify it has loaded in the decompiler terminal
```
[Binsync] v2.1.0 loaded
```

If it does not show, it means the plugin is not in the plugins folder. 

3. Open the BinSync Config Pane
   1. You can hit `Ctrl+Shift+B` to open it, OR
   2. You can click your decompiler menu: `Edit -> Plugins -> Binsync: settings`. On Binja it's under `Tools`.
   
4. Give a username and find the example_repo from earlier, click ok
   ![](./assets/images/demo1.png)
   
5. Verify your terminal says (with your username):
```bash
[BinSync]: Client has connected to sync repo with user: <username>.
```

6. You should now see an Info Panel. Click on `Activity`, you can see other user's activities. You should also notice
   your username on the bottom right of the panel to be green (online).
   ![](./assets/images/demo2.png)

Congrats, your BinSync seems to connect to a repo, and recognize you as a user.
Let's test pulling to verify you can actually do stuff with your install. 

7. In your decompiler, click anywhere in the function `main` once. After a second or two you should notice on the
   Info Panel that the words on the bottom left say `main@0x40071d`. This is your context.
   
8. Now click on the `Context` tab, and right click on the user `mahaloz`. Click the `Sync` popup.
   ![](./assets/images/demo3.png)
   
9. If everything works out, your decompilation should've changed for `main`. Now the function should be named
   `mahaloz_main`, and it should look something like:
   
```c
// ***
// This is a function comment:
// 
// Thanks for using BinSync <3
// 
// - mahaloz
// ***
int __cdecl mahaloz_main(int argc, const char **argv, const char **envp)
{
  int buf; 
  mahalo_struct special_stack_var; 
  char username[16]; 

  username[8] = 0;
  LOBYTE(special_stack_var.field_8) = 0;
  puts("Username: ");
  read(0, username, 8uLL);
  read(0, &buf, 1uLL);
  puts("Password: ");                           // totally a password
  read(0, &special_stack_var, 8uLL);
  read(0, &buf, 1uLL);
  buf = authenticate(username, &special_stack_var);
  if ( !buf )
    rejected(username);
  return accepted(username);
} 
```

Take note of the variable names & types, and the comments. This will look different per-decompiler, but the symbols and
types should line up for the most part.

For more general use, tips, and advice, see our Wiki for full help.



### Git Prereqs

BinSync's backbone is `git`, which means to use BinSync you must have two things:
1. `git` must be installed on your system.
2. You must use an ssh key to pull and push, AND **it must be password unlocked**.

Number 2 is very important. Many users have complained about BinSync not auto pushing/pulling
things with git and almost all of them did not have their ssh key unlocked. If your key requires you 
to enter a password, you have two options:

1. pull some private repo once so you need to enter your password and unlock the key
2. generate a new key that is not password protected and add it to GitHub (or whatever host you use)

### Manual Install Without Scripts (Windows)
If you are unable to use Bash for whatever reason, the install script only does two things for
every decompiler:
1. Copy the entire folder in `plugins/decoilername_binsync/` to the decompiler plugin folder
2. Install BinSync to the same python the decompiler uses `python3 -m pip install --user -e .`

## Usage  
### Verifying your download works
1. Make a place for sync repos to live
```bash
mkdir ~/sync_repos
cd ~/sync_repos
```
2. Download the testing repo and get the binary out (fauxware)
```bash
```
3. Launch IDA on fauxware
4. Verify your IDAPython terminal says:
```bash
[Binsync] v2.1.0 loaded!
```