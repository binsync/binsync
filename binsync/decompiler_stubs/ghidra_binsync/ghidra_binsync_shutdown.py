# Shutsdown the BinSync dependent Ghidra Bridge server
# @author BinSync
# @category BinSync
# @menupath Tools.BinSync.Shutdown BS Backend

from binsync_vendored.jfx_bridge import bridge
from binsync_vendored.ghidra_bridge_port import DEFAULT_SERVER_PORT

if __name__ == "__main__":
    print("Requesting server shutdown")
    b = bridge.BridgeClient(
        connect_to_host="127.0.0.1", connect_to_port=DEFAULT_SERVER_PORT
    )

    print(b.remote_shutdown())