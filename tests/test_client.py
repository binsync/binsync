import os
import sys
import tempfile

import unittest

import binsync


class TestClient(unittest.TestCase):
    def test_client_creation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = binsync.Client("user0", tmpdir, "fake_hash", init_repo=True)
            self.assertTrue(os.path.isdir(os.path.join(tmpdir, ".git")))

    def test_client_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = binsync.Client("user0", tmpdir, "fake_hash", init_repo=True)

            state = client.get_state()
            self.assertEqual(state.user, "user0")
            # after create, state is dirty
            self.assertTrue(state.dirty)

            func_header = binsync.data.FunctionHeader("some_name", 0x400080)
            state.set_function_header(func_header)
            # it should be dirty still (more edits)
            self.assertTrue(state.dirty)

            # commit changes so we clean it!
            client.commit_state(state)
            self.assertFalse(state.dirty)

            state = client.get_state(user="user0")
            self.assertTrue(len(state.functions), 1)
            self.assertTrue(state.functions[0x400080].header, func_header)

            # git is still running at least on windows
            client.close()


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
