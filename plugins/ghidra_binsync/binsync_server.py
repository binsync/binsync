import binsync
REPO_PATH="/tmp"

# start a binsync client
sync_client = binsync.Client("ghidra_0", REPO_PATH, "")


def on_pull_request(username):
    sync_client.get_state(user=username)
