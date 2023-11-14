# Starts the BinSync UI and the Ghidra backend server.
# @author BinSync
# @category BinSync
# @menupath Tools.BinSync.Start BinSync
# @toolbar binsync_vendored/binsync.png

import subprocess
from binsync_vendored.ghidra_bridge_server import GhidraBridgeServer


def start_bs_ui():
    subprocess.Popen("binsync --run-decompiler-ui ghidra".split(" "))


if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=True)
    start_bs_ui()
