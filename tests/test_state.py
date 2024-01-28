import tempfile
import os
import sys

import unittest

from binsync.core.client import Client
from libbs.artifacts import (
    FunctionHeader, Struct,
)
from binsync.core.state import State, ArtifactType


class TestState(unittest.TestCase):

    def test_state_creation(self):
        state = State("user0")
        self.assertEqual(state.user, "user0")

    def test_state_dumping(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # create a client only for accurate git usage
            client = Client("user0", tmpdir, "fake_hash", init_repo=True)
            state = State("user0", client=client)

            # dump to the current repo, current branch
            state.dump(client.repo.index)
            metadata_path = os.path.join(tmpdir, "metadata.toml")
            self.assertTrue(os.path.isfile(metadata_path))

    def test_state_loading(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # create a client only for accurate git usage
            client = Client("user0", tmpdir, "fake_hash", init_repo=True)
            state = State("user0", client=client)

            # create a state for dumping
            state.version = 1
            func_header = FunctionHeader("some_name", 0x400080)
            state.set_function_header(func_header)

            # dump and commit state to tree
            client._commit_state(state)

            # load the state
            state_tree = client._get_tree(state.user, client.repo)
            new_state = State.parse(state_tree, client=client)

            self.assertEqual(new_state.user, "user0")
            self.assertEqual(new_state.version, 1)
            self.assertEqual(len(new_state.functions), 1)
            self.assertEqual(new_state.functions[0x400080].header, func_header)

    def test_state_last_push(self):
        state = State("user0")

        func1 = FunctionHeader("some_name", 0x400080)
        func2 = FunctionHeader("some_other_name", 0x400090)
        struct = Struct("some_struct", 8, [])

        state.set_function_header(func1, set_last_change=True)
        state.set_struct(struct)
        # simulate pulling from another user
        state.set_function_header(func2, set_last_change=False)

        self.assertEqual(state.functions[0x400090].last_change, None)
        self.assertNotEqual(state.functions[0x400080].last_change, None)
        self.assertNotEqual(state.structs["some_struct"].last_change, None)

        self.assertNotEqual(state.last_push_time, None)
        self.assertEqual(state.last_push_artifact, "some_struct")
        self.assertEqual(state.last_push_artifact_type, ArtifactType.STRUCT)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
