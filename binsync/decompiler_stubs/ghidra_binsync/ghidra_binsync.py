# Starts the BinSync UI and the Ghidra backend server.
# @author BinSync
# @category BinSync
# @menupath Tools.Binsync.Start BinSync
# @toolbar python.png

import subprocess
from binsync_vendored.ghidra_bridge_server import GhidraBridgeServer


def start_bs_ui():
    subprocess.Popen("binsync --run-plugin ghidra".split(" "))


if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=True)
    start_bs_ui()
