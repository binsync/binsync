
import tempfile
import os

import nose.tools

import binsync


def test_state_creation():
    state = binsync.State("user0")
    nose.tools.assert_equal(state.user, "user0")


def test_state_dumping():
    state = binsync.State("user0")

    with tempfile.TemporaryDirectory() as tmpdir:
        state.dump(tmpdir)

        metadata_path = os.path.join(tmpdir, "metadata.toml")
        nose.tools.assert_true(os.path.isfile(metadata_path))


def test_state_loading():
    state = binsync.State("user0")
    state.version = 1
    func = binsync.data.Function(0x400080, "some_name", "some comment")
    state.functions[func.addr] = func

    # dump the state
    with tempfile.TemporaryDirectory() as tmpdir:
        state.dump(tmpdir)

        # load the state
        new_state = binsync.State.parse(tmpdir)

        nose.tools.assert_equal(new_state.user, "user0")
        nose.tools.assert_equal(new_state.version, 1)
        nose.tools.assert_equal(len(new_state.functions), 1)
        nose.tools.assert_equal(new_state.functions[0x400080], func)


if __name__ == "__main__":
    test_state_creation()
    test_state_dumping()
    test_state_loading()
