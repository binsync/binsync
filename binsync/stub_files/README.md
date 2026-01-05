
## BinSync

<p align="center">
   <img src="https://i.imgur.com/qdesKpg.png" style="width: 10%;" alt="BinSync Logo"/>
</p>

BinSync is a decompiler collaboration tool built on the Git versioning system to enable fined-grained reverse
engineering collaboration regardless of decompiler. 
BinSync is supported in IDA, Binary Ninja, Ghidra, and angr-management.

![Demo](https://github.com/binsync/binsync/blob/main/assets/images/binja_sync.gif?raw=true)

## Overview 
At a high level, BinSync works by tracking changes to important reverse engineering artifacts 
(functions, comments, types) while you reverse engineer a binary. These changes are then committed to a Git repository.
The data is stored in TOMLS and is therefore human-readable and diffable. The data stored, such as types, are 
converted to C so they can be transferred between decompilers. 
An example repo of this format can be found at [https://github.com/binsync/example.bsproj](https://github.com/binsync/example.bsproj). 

BinSync provides a GUI for you to view changes made by you and other users and synchronize them.
BinSync also has other extra features for integrating AI reverse engineering assistants.

## Installation & Usage
BinSync can be installed directly from within your decompiler's plugin manager. After that initial installation, you
can verify that your installation works by following our quickstart guide to join our example project.
The 5-minute quickstart guide can be found [here](https://docs.binsync.net/quickstart/joining-project), and is 
always the most up-to-date way to get started with BinSync.

## Credits
BinSync is built by [mahaloz](https://github.com/mahaloz), the [angr](https://angr.io) team, and the [SEFCOM](https://sefcom.asu.edu) research lab. It's also due
in large part to its use by the [Shellphish](https://shellphish.net) hacking team. The BinSync Team can be listed as follows:
- Zion Leonahenahe Basque (mahaloz)
- The angr team
- The SEFCOM Lab at Arizona State University

For inquiries, contact the project lead, Zion Leonahenahe Basque, aka, "mahaloz" at binsync@mahaloz.re. 