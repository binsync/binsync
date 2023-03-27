# BinSync Ghidra Plugin
## Install
First make sure you have BinSync installed on your local python3
```bash
python3 -m pip install binsync
```

Next grab the Ghidra BinSync plugin from the releases tab and move it to your Ghidra install:
```bash
wget https://github.com/mahaloz/binsync-ghidra-plugin/releases/download/v1.0.0/ghidra_10.1.4_PUBLIC_20220918_binsync-ghidra-plugin.zip
```

Now you will need to add the Extension then enable in Ghidra through `File->Install Extension...`. 

## Usage
After you have installed and enabled the extension, simply hit `Ctrl+Shift+B` in your decompiler and it should open a configuration panel.


## Hacking
You should use [Eclipse IDE](https://www.eclipse.org/downloads/) and setup GhidraDev which is described in the [GhidraDev Readme](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/GhidraDev_README.html).

After seting up GhidraDev, you can use the `Run` button in Eclipse which will give you an option to load Ghidra with the Extension. The extension will
be auto copied into the Ghidra dir, all you need to do is enable it. 