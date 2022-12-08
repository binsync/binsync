from typing import Optional, Set
from pathlib import Path
import subprocess
import shlex
import json
import sys
import os

import virtualenv


binsync_dir = Path.home() / ".binsync"


class Venv:
    """
    A python virtual env and its paths
    """
    def __init__(self, root: Path):
        self.root = root
        init = not self.root.exists()
        if init:
            virtualenv.cli_run([str(self.root)])
        self.site_packages: Path = next((self.root / "lib").glob("python3.*")) / "site-packages"
        self.site_packages_base: Path = self.site_packages.parent / "site-packages-base"
        if init:
            self.site_packages.rename(self.site_packages_base)
            self.site_packages.mkdir()
        self.python: Path = self.root / "bin" / "python"
        self.pip: Path = self.root / "bin" / "pip"


class Pip:
    """
    Wrap pip of a Venv
    """
    def __init__(self, venv: Venv):
        self.venv = venv
        env = { i:k for i,k in os.environ.items() }
        pth: str = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{pth}{(':' if pth else '')}{self.venv.site_packages_base}"
        env["INVOKED_VIA_BINSYNC_CLI"] = "1"
        self._env = env

    def _invoke(self, cmd: str) -> None:
        subprocess.run(args=(self.venv.python, "-c", cmd), stderr=subprocess.STDOUT, env=self._env)

    def __call__(self, *args, print_output: bool = True) -> Optional[str]:
        p = subprocess.run(
            [ self.venv.pip, *args ],
            env=self._env,
            capture_output=not print_output,
        )
        if not print_output:
            return p.stdout

    def _list(self, print_output: bool) -> Optional[Set[str]]:
        fmt = [] if print_output else ["--format", "json"]
        r = self("list", *fmt, "--path", self.venv.site_packages, print_output=print_output)
        if r is not None:
            return { i["name"].replace("-", "_") for i in json.loads(r) }

    def list(self) -> None:
        self._list(True)

    def uninstall(self, pkg: str) -> None:
        print("TODO: .uninstall() hooks for dependent packags too") # TODO: fix me
        if pkg not in self._list(False):
            raise RuntimeError(f"{pkg} is either not installed or not managed by binsync")
        print(f"Uninstalling hooks for: {pkg}")
        self._invoke(f"import {pkg}; {pkg}.uninstall()")
        self("uninstall", "-y", pkg)

    def install(self, *args: str) -> None:
        if len(args) == 0:
            raise RuntimeError("install given no arguments")
        what = [i for i in args if not i.startswith("-")]
        assert len(what) == 1, "exactly one package is required"
        pkg = what[0]
        flags = [i for i in args if i.startswith("-")]
        assert len(flags) <= 1, "bad flags"
        for i in flags:
            assert i in ("-e", "-U", "--editable", "--upgrade"), "bad flag"
        flags = ["--no-build-isolation", "--no-index"] + flags
        # Install
        installed = self._list(False)
        self("install", *flags, pkg)
        for i in (self._list(False) - installed):
            if i.startswith("binsync_plugin_"): # TODO: . instead of -
                print(f"Installing hooks for: {i}")
                self._invoke(f"import {i}; {i}.install()")


def main(argv):
    # TODO: For testing, we disable indexing via --no-index
    # TODO: use argparse to pass actual args

    pip = Pip(Venv(binsync_dir / "venv"))
    fns = {
        "list" : pip.list,
        "uninstall" : pip.uninstall,
        "install" : pip.install,
    }
    if len(argv) < 2:
        print("Too few args")
    fns[argv[1]](*argv[2:])


def cli():
    return main(sys.argv)
