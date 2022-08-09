import os
import sys
import tempfile

import unittest

import binsync
from binsync import FunctionArgument, FunctionHeader, StackVariable
import logging

_l = logging.getLogger(name=__name__)

class TestClient(unittest.TestCase):
    def test_large_state_creation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            master_client = binsync.Client("user0", tmpdir, "fake_hash", init_repo=True)
            self.assertTrue(os.path.isdir(os.path.join(tmpdir, ".git")))

            func1 = FunctionHeader("func", 0x400000, ret_type="int *", args={
                0: FunctionArgument(0, "a1", "int", 4), 1: FunctionArgument(1, "a2", "long", 8)
            })

            userlist = [f"user{id}" for id in range(1,10)]

            for user in userlist:
                u_func1 = func1.copy()
                uc = binsync.Client(user, tmpdir, "fake_hash", init_repo=False, enforce_repo_lock=False)
                state = uc.get_state()
                u_func1.name = f"func_{user}"
                print(u_func1.name)
                state.set_function_header(u_func1)
                state.functions[func1.addr].size = 0x100

                stack_vars = {
                    0x0: StackVariable(0, 3, "v0", "int", 4, u_func1.addr),
                    0x4: StackVariable(4, 3, "v4", "int", 4, u_func1.addr)
                }
                for off, var in stack_vars.items():
                    state.set_stack_variable(var)
                _l.critical(f"pushing for {user}")
                uc.commit_state(state, msg=f"Test Commit for {user}")
                print(state)

            master_client.update()
            for user in userlist:
                state = master_client.get_state(user=user)
                func = state.get_function(func1.addr)
                print(f"USER {user} FNAME {func.name}")



if __name__ == "__main__":
    unittest.main(argv=sys.argv)