import tempfile
import os
import sys
import json

import unittest

import binsync
from binsync.data import Function, FunctionHeader, StackVariable, FunctionArgument, Comment


class TestState(unittest.TestCase):

    def test_state_creation(self):
        state = binsync.State("user0")
        self.assertEqual(state.user, "user0")

    def test_state_dumping(self):

        with tempfile.TemporaryDirectory() as tmpdir:
            # create a client only for accurate git usage
            client = binsync.Client("user0", tmpdir, "fake_hash", init_repo=True)
            state = binsync.State("user0")
            client.state = state

            # dump to the current repo, current branch
            state.dump(client.repo.index)
            metadata_path = os.path.join(tmpdir, "metadata.toml")
            self.assertTrue(os.path.isfile(metadata_path))

    def test_state_loading(self):
        # create a state for dumping
        state = binsync.State("user0")
        state.version = 1
        func_header = binsync.data.FunctionHeader("some_name", 0x400080)
        state.set_function_header(func_header)

        with tempfile.TemporaryDirectory() as tmpdir:
            # create a client only for accurate git usage
            client = binsync.Client("user0", tmpdir, "fake_hash", init_repo=True)
            client.state = state

            # dump and commit state to tree
            client.commit_state(state)

            # load the state
            state_tree = client.get_tree(state.user)
            new_state = binsync.State.parse(state_tree)

            self.assertEqual(new_state.user, "user0")
            self.assertEqual(new_state.version, 1)
            self.assertEqual(len(new_state.functions), 1)
            self.assertEqual(new_state.functions[0x400080].header, func_header)

    def test_state_last_push(self):
        state = binsync.State("user0")

        func1 = binsync.data.FunctionHeader("some_name", 0x400080)
        func2 = binsync.data.FunctionHeader("some_other_name", 0x400090)
        struct = binsync.data.Struct("some_struct", 8, [])

        state.set_function_header(func1, set_last_change=True)
        state.set_struct(struct, None)
        # simulate pulling from another user
        state.set_function_header(func2, set_last_change=False)

        self.assertEqual(state.functions[0x400090].last_change, None)
        self.assertNotEqual(state.functions[0x400080].last_change, None)
        self.assertNotEqual(state.structs["some_struct"].last_change, None)

        self.assertNotEqual(state.last_push_time, None)
        self.assertEqual(state.last_push_artifact, "some_struct")
        self.assertEqual(state.last_push_artifact_type, binsync.state.ArtifactType.STRUCT)

    def test_func_diffing(self):
        state1 = binsync.State("user1")
        state2 = binsync.State("user2")

        # setup top
        func1 = FunctionHeader("func", 0x400000, ret_type="int *", args={
            0: FunctionArgument(0, "a1", "int", 4), 1: FunctionArgument(1, "a2", "long", 8)
        })
        func2 = FunctionHeader("func_changed", func1.addr, ret_type="long *", args={
            0: FunctionArgument(0, "a1", "int", 4), 1: FunctionArgument(1, "a2", "int", 4)
        })

        state1.set_function_header(func1)
        state2.set_function_header(func2)
        state1.functions[func1.addr].size = 0x100
        state2.functions[func1.addr].size = 0x150

        stack_vars1 = {
            0x0: StackVariable(0, 3, "v0", "int", 4, func1.addr),
            0x4: StackVariable(4, 3, "v4", "int", 4, func1.addr)
        }
        stack_vars2 = {
            0x0: StackVariable(0, 3, "v0", "int", 4, func1.addr),
            0x4: StackVariable(4, 3, "v4", "long", 8, func1.addr),
            0x8: StackVariable(4, 3, "v8", "long", 8, func1.addr)
        }

        for stack_vars_info in [(stack_vars1, state1), (stack_vars2, state2)]:
            state = stack_vars_info[1]
            stack_vars = stack_vars_info[0]
            for off, var in stack_vars.items():
                state.set_stack_variable(var, off, var.addr)

        func1 = state1.get_function(func1.addr)
        func2 = state2.get_function(func1.addr)

        diff_dict = func1.diff(func2)
        header_diff = diff_dict["header"]
        vars_diff = diff_dict["stack_vars"]

        # size should not match
        self.assertNotEqual(func1.size, func2.size)
        self.assertEqual(diff_dict["size"]["before"], func1.size)
        self.assertEqual(diff_dict["size"]["after"], func2.size)

        # names should not match
        self.assertEqual(header_diff["name"]["before"], func1.name)
        self.assertEqual(header_diff["name"]["after"], func2.name)

        # arg1 should match
        self.assertFalse(header_diff["args"][0])

        # arg2 should not match
        self.assertNotEqual(header_diff["args"][1]["type_str"]["before"], header_diff["args"][1]["type_str"]["after"])

        # v4 and v8 should differ
        for off, var_diff in vars_diff.items():
            if off == 0:
                self.assertFalse(var_diff)
            if off == 0x4:
                self.assertNotEqual(var_diff["size"]["before"], var_diff["size"]["after"])
            elif off == 0x8:
                self.assertIsNone(var_diff["addr"]["before"])
                self.assertEqual(var_diff["addr"]["after"], func1.addr)

        print(json.dumps(diff_dict, sort_keys=False, indent=4))


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
