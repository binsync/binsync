
import tempfile
import os

import nose.tools

import binsync


def test_client_creation():
    with tempfile.TemporaryDirectory() as tmpdir:
        client = binsync.Client("user0", tmpdir)

        nose.tools.assert_true(os.path.isdir(os.path.join(tmpdir, ".git")))


def test_client_state():
    # with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir = tempfile.mkdtemp()
    client = binsync.Client("user0", tmpdir)

    state = client.get_state()
    nose.tools.assert_equal(state.user, "user0")

    func = binsync.data.Function(0x400080, name="some_name", comment="some comment!")
    # the state should be clean
    nose.tools.assert_false(state._dirty)
    state.set_function(func)
    # it should be dirty now
    nose.tools.assert_true(state._dirty)
    client.save_state()

    client.state = None
    state = client.get_state()

    nose.tools.assert_equal(len(state.functions), 1)
    nose.tools.assert_equal(state.functions[0x400080], func)

    client.close()  # git is still running at least on windows


if __name__ == "__main__":
    test_client_creation()
    test_client_state()
