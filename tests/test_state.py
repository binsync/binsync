import tempfile
import os
import sys
import json

import unittest

from binsync.core.client import Client
from libbs.artifacts import (
    FunctionHeader, StackVariable, FunctionArgument, Struct,
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

    def test_func_diffing(self):
        state1 = State("user1")
        state2 = State("user2")

        # setup top
        func1 = FunctionHeader("func", 0x400000, type_="int *", args={
            0: FunctionArgument(0, "a1", "int", 4), 1: FunctionArgument(1, "a2", "long", 8)
        })
        func2 = FunctionHeader("func_changed", func1.addr, type_="long *", args={
            0: FunctionArgument(0, "a1", "int", 4), 1: FunctionArgument(1, "a2", "int", 4)
        })

        state1.set_function_header(func1)
        state2.set_function_header(func2)
        state1.functions[func1.addr].size = 0x100
        state2.functions[func1.addr].size = 0x150

        stack_vars1 = {
            0x0: StackVariable(0, "v0", "int", 4, func1.addr),
            0x4: StackVariable(4, "v4", "int", 4, func1.addr)
        }
        stack_vars2 = {
            0x0: StackVariable(0, "v0", "int", 4, func1.addr),
            0x4: StackVariable(4, "v4", "long", 8, func1.addr),
            0x8: StackVariable(8, "v8", "long", 8, func1.addr)
        }

        for stack_vars_info in [(stack_vars1, state1), (stack_vars2, state2)]:
            stack_vars, state = stack_vars_info[:]
            for off, var in stack_vars.items():
                state.set_stack_variable(var)

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
        self.assertNotEqual(header_diff["args"][1]["type"]["before"], header_diff["args"][1]["type"]["after"])

        # v4 and v8 should differ
        offsets = [0, 4, 8]
        for off in offsets:
            var_diff = vars_diff[off]
            if off == 0:
                self.assertFalse(var_diff)
            if off == 0x4:
                self.assertNotEqual(var_diff["size"]["before"], var_diff["size"]["after"])
            elif off == 0x8:
                self.assertIsNone(var_diff["addr"]["before"])
                self.assertEqual(var_diff["addr"]["after"], func1.addr)

        print(json.dumps(diff_dict, sort_keys=False, indent=4))

    def test_nonconflicting_funcs(self):
        state1 = State("user1")
        state2 = State("user2")

        # setup top
        func1 = FunctionHeader("user1_func", 0x400000, type_="int *", args={})
        func2 = FunctionHeader("main", func1.addr, type_="long *", args={})

        state1.set_function_header(func1)
        state2.set_function_header(func2)
        state1.functions[func1.addr].size = 0x100
        state2.functions[func1.addr].size = 0x100

        stack_vars1 = {
            0x0: StackVariable(0, "v0", "int", 4, func1.addr),
            0x4: StackVariable(4, "my_var", "int", 4, func1.addr)
        }
        stack_vars2 = {
            0x0: StackVariable(0, "v0", "int", 4, func1.addr),
            0x4: StackVariable(4, "v4", "long", 8, func1.addr),
            0x8: StackVariable(8, "v8", "long", 8, func1.addr)
        }

        for stack_vars_info in [(stack_vars1, state1), (stack_vars2, state2)]:
            state = stack_vars_info[1]
            stack_vars = stack_vars_info[0]
            for off, var in stack_vars.items():
                state.set_stack_variable(var)
        
        func1, func2 = state1.get_function(0x400000), state2.get_function(0x400000) 
        merge_func = func1.nonconflict_merge(func2)

        self.assertEqual(merge_func.name, "user1_func")
        self.assertEqual(merge_func.header.type, "int *")
        self.assertEqual(merge_func.stack_vars[0].name, "v0")
        self.assertEqual(merge_func.stack_vars[4].name, "my_var")
        self.assertEqual(merge_func.stack_vars[4].type, "int")
        self.assertEqual(merge_func.stack_vars[8].name, "v8")


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
