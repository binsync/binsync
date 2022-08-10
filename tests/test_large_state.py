import datetime
import os
import sys
import tempfile
import random
import time
import unittest
import glob
import binsync
from binsync import FunctionArgument, FunctionHeader, StackVariable
import logging
from decompile_angr import parse_binary
import toml
import json

_l = logging.getLogger(name=__name__)
handler = logging.StreamHandler(sys.stdout)
_l.addHandler(handler)
_l.setLevel("DEBUG")

# blacklist: binaries not supported by angr
blacklist = ['gopher_coin_go']

filename = "fauxware"
user_count = 3
test_start = int(time.time())

class TestClient(unittest.TestCase):
    def random_ts(self):
        return test_start + random.randint(0, 120*60)
    
    def test_large_state_creation(self):
        def generate_toml_files():
            base_directory = os.path.dirname(os.path.abspath(__file__))
            binaries_directory = os.path.join(base_directory, 'binaries')
            toml_directory = os.path.join(base_directory, 'toml')
            for filename in os.listdir(binaries_directory):
                # Skip binaries in blacklist
                if filename in blacklist:
                    continue
                binary_path = os.path.join(binaries_directory, filename)
                toml_path = os.path.join(toml_directory, filename + '.toml')
                # checking if it is a file
                if os.path.isfile(binary_path):
                    # check if the toml file already exists
                    if not os.path.exists(toml_path):
                        print("Generating the toml file for %s" % filename)
                        parse_binary(binary_path, toml_path)

        generate_toml_files()
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

    
    def test_toml_to_binsync_state(self):
        _l.info("\n")
        files = glob.glob("toml/*")

        for filename in files:
            with open(filename) as f:
                data = toml.loads(f.read())
                _l.info(f"Loaded TOML file {filename}")
            if data is None:
                assert False, f"ERROR loading supplied toml file {filename}"

            functions = data.get("functions", None)
            if not functions:
                assert False, "Failed to find functions in loaded toml file"

            binname = data.get("binary", "UNKNOWN")
            binhash = data.get("md5", None)
            if not binhash:
                assert False, "Failed to find md5 hash in loaded toml file (key 'md5')"

            func_list = []
            for addr, func in functions.items():
                faddr = int(addr)
                fname = func.get("name", None)
                vars = func.get("variables", [])
                args = func.get("arguments", [])
                ret_type = func.get("return_type", "void *")
                fargs = {}
                c = 0
                for arg in args:
                    aidx = c
                    aname = arg.get("name", None)
                    atype = arg.get("type", "void *")
                    asize = arg.get("size", 8)

                    fargs[aidx] = FunctionArgument(aidx, aname, atype, asize)

                    c += 1

                ufunc = FunctionHeader(fname, faddr, ret_type=ret_type, args=fargs)

                _l.info(f"SUCCESSFULLY LOADED: {ufunc}")

                func_list.append(ufunc)

            with tempfile.TemporaryDirectory() as tmpdir:
                master_client = binsync.Client("user0", tmpdir, binhash, init_repo=True)

                self.assertTrue(os.path.isdir(os.path.join(tmpdir, ".git")))

                mcs = master_client.get_state()

                for f in func_list:
                    mcs.set_function_header(f)

                userlist = [f"user{id}" for id in range(1,user_count)]

                for user in userlist:
                    uc = binsync.Client(user, tmpdir, binhash, init_repo=False, enforce_repo_lock=False)
                    ustate = uc.get_state()
                    for f in func_list:
                        fc = f.copy()
                        fc.name = f"{fc.name}_{user}"
                        fc.last_change = self.random_ts()
                        _l.info(f"{user} {fc.name}: {fc.last_change}")
                        ustate.set_function_header(fc, set_last_change=False)
                        ustate.functions[fc.addr].last_change = fc.last_change
                    uc.commit_state(ustate)
                master_client.update()

                for user in userlist:
                    ustate = master_client.get_state(user=user)
                    _l.info(f"user: {user}, {ustate.functions}, {ustate}")
                    for addr, func in ustate.functions.items():
                        _l.info(f"{type(func.last_change)}")
                        _l.info(f"{user}: {addr:#0x}({addr}), {func.name}, {repr(func.last_change)}")





                # for user in userlist:
                #     u_func1 = func1.copy()
                #     uc = binsync.Client(user, tmpdir, "fake_hash", init_repo=False, enforce_repo_lock=False)
                #     state = uc.get_state()
                #     u_func1.name = f"func_{user}"
                #     print(u_func1.name)
                #     state.set_function_header(u_func1)
                #
                #     stack_vars = {
                #         0x0: StackVariable(0, 3, "v0", "int", 4, u_func1.addr),
                #         0x4: StackVariable(4, 3, "v4", "int", 4, u_func1.addr)
                #     }
                #     for off, var in stack_vars.items():
                #         state.set_stack_variable(var)
                #     _l.critical(f"pushing for {user}")
                #     uc.commit_state(state, msg=f"Test Commit for {user}")
                #     print(state)
                #
                # master_client.update()
                # for user in userlist:
                #     state = master_client.get_state(user=user)
                #     func = state.get_function(func1.addr)
                #     print(f"USER {user} FNAME {func.name}")





if __name__ == "__main__":
    unittest.main(argv=sys.argv)
