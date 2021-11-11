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
            # after create, state is not dirty
            self.assertFalse(state.dirty)

            func = binsync.data.Function(0x400080, name="some_name")
            state.set_function(func)
            # it should be dirty now
            self.assertTrue(state.dirty)

            # commit changes so we clean it!
            client.commit_state()
            self.assertFalse(state.dirty)

            # destroy the old state to see if data persits
            client.state = None
            state = client.get_state()
            self.assertTrue(len(state.functions), 1)
            self.assertTrue(state.functions[0x400080], func)

            # git is still running at least on windows
            client.close()


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
