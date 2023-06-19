import os
from pathlib import Path
import textwrap
import pkg_resources
import shutil
from urllib.request import urlretrieve

from binsync.data.configuration import GlobalConfig

from prompt_toolkit import prompt
from prompt_toolkit.completion.filesystem import PathCompleter

class Color:
    """
    Used to colorify terminal output.
    Taken from: https://github.com/hugsy/gef/blob/dev/tests/utils.py
    """
    NORMAL = "\x1b[0m"
    GRAY = "\x1b[1;38;5;240m"
    LIGHT_GRAY = "\x1b[0;37m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    PINK = "\x1b[35m"
    CYAN = "\x1b[36m"
    BOLD = "\x1b[1m"
    UNDERLINE = "\x1b[4m"
    UNDERLINE_OFF = "\x1b[24m"
    HIGHLIGHT = "\x1b[3m"
    HIGHLIGHT_OFF = "\x1b[23m"
    BLINK = "\x1b[5m"
    BLINK_OFF = "\x1b[25m"


class Installer:
    DECOMPILERS = (
        "ida",
        "binja",
        "ghidra",
        "angr"
    )

    DEBUGGERS = (
        "gdb",
    )

    def __init__(self, targets=None, target_install_paths=None):
        self.targets = targets or self.DECOMPILERS+self.DEBUGGERS
        self._home = Path(os.getenv("HOME") or "~/").expanduser().absolute()
        self.target_install_paths = target_install_paths or self._populate_installs_from_config()

    def _populate_installs_from_config(self):
        config = GlobalConfig.update_or_make(self._home)
        if not config:
            return {}

        return {
            attr: getattr(config, attr) for attr in config.__slots__
        }

    def install(self):
        self.display_prologue()
        try:
            self.install_all_targets()
        except Exception as e:
            print(f"Stopping Install... because: {e}")
        self.display_epilogue()

    def display_prologue(self):
        pass

    def display_epilogue(self):
        self.good("Install completed! If anything was skipped by mistake, please manually install it.")

    @staticmethod
    def info(msg):
        print(f"{Color.BLUE}{msg}{Color.NORMAL}")

    @staticmethod
    def good(msg):
        print(f"{Color.GREEN}[+] {msg}{Color.NORMAL}")

    @staticmethod
    def warn(msg):
        print(f"{Color.YELLOW}[!] {msg}{Color.NORMAL}")

    @staticmethod
    def ask_path(question):
        Installer.info(question)
        filepath = prompt("", completer=PathCompleter(expanduser=True))

        if not filepath:
            return None

        filepath = Path(filepath).expanduser().absolute()
        if not filepath.exists():
            Installer.warn(f"Provided filepath {filepath} does not exist.")
            return None

        return filepath

    @staticmethod
    def link_or_copy(src, dst, is_dir=False, symlink=False):
        # clean the install location
        shutil.rmtree(dst, ignore_errors=True)
        try:
            os.unlink(dst)
        except:
            pass

        if not symlink:
            # copy if symlinking is not available on target system
            if is_dir:
                shutil.copytree(src, dst)
            else:
                shutil.copy(src, dst)
        else:
            # first attempt a symlink, if it works, exit early
            try:
                os.symlink(src, dst, target_is_directory=is_dir)
                return
            except:
                pass

    def install_all_targets(self):
        for target in self.targets:
            try:
                installer = getattr(self, f"install_{target}")
            except AttributeError:
                continue

            path = self.target_install_paths.get(f"{target}_path", None)
            if path:
                path = Path(path).expanduser().absolute()

            res = installer(path=path)
            if res is None:
                self.warn(f"Skipping or failed install for {target}... {Color.NORMAL}\n")
            else:
                self.good(f"Installed {target} to {res}\n")
                GlobalConfig.update_or_make(self._home, **{f"{target}_path": res.parent})

    def install_ida(self, path=None):
        ida_path = path or self._home.joinpath(".idapro")
        ida_plugin_path = ida_path.joinpath("plugins").expanduser()
        default_str = f" [default = {ida_plugin_path}]"
        if not ida_plugin_path.exists():
            if ida_path.exists():
                os.makedirs(ida_plugin_path)
            else:
                ida_plugin_path = None
                default_str = ""

        path = self.ask_path(f"IDA Plugins Path{default_str}:")
        if not path:
            if not ida_plugin_path:
                return None

            path = ida_plugin_path

        if not path.absolute().exists():
            return None

        return path

    def install_ghidra(self, path=None):
        path = self._home.joinpath('ghidra_scripts').expanduser()
        default_str = f" [default = {path}]"
        ghidra_default_path = path
        path = self.ask_path(f"Ghidra Scripts Path{default_str}:")
        if path:
            path = path.joinpath("Extensions").joinpath("Ghidra")
        elif ghidra_default_path:
            path = ghidra_default_path
        else:
            return None

        if not path.absolute().exists():
            return None

        return path

    def install_binja(self, path=None):
        binja_install_path = path or self._home.joinpath(".binaryninja").joinpath("plugins").expanduser()
        default_str = f" [default = {binja_install_path}]"
        if not binja_install_path.exists():
            binja_install_path = None
            default_str = ""

        path = self.ask_path(f"Binary Ninja Plugins Path{default_str}:")
        if not path:
            if not binja_install_path:
                return None

            path = binja_install_path

        return path

    def install_angr(self, path=None):
        # look for a default install
        # attempt to resolve through packaging
        angr_resolved = True
        try:
            import angrmanagement
        except ImportError:
            angr_resolved = False

        default_str = ""
        angr_install_path = None
        if angr_resolved:
            angr_install_path = Path(angrmanagement.__file__).parent
            default_str = f" [default = {angr_install_path}]"
        elif path:
            angr_install_path = path
            default_str = f" [default = {angr_install_path}]"

        # use the default if possible
        # TODO: this needs to be changed so we can still provide the install path if non-interactive,
        # but also introduce a default_path kwarg to all these installers
        path = self.ask_path(f"angr-management Install Path{default_str}:") if path is None else path
        if not path:
            if not angr_install_path:
                return None

            path = angr_install_path

        path = path.joinpath("plugins")
        if not path.absolute().exists():
            return None

        return path

    def install_gdb(self, path=None):
        default_gdb_path = path or self._home.joinpath(".gdbinit").expanduser()
        default_str = f" [default = {default_gdb_path}]"
        path = self.ask_path(f"gdbinit path{default_str}:") if path is None else path
        if not path:
            if not default_gdb_path:
                return None

            path = default_gdb_path

        return path


class BinSyncInstaller(Installer):
    def __init__(self):
        super().__init__(targets=Installer.DECOMPILERS)
        self.plugins_path = Path(
            pkg_resources.resource_filename("binsync", f"decompiler_stubs")
        )

    def display_prologue(self):
        print(textwrap.dedent("""
         _____ _     _____             
        | __  |_|___|   __|_ _ ___ ___ 
        | __ -| |   |__   | | |   |  _|
        |_____|_|_|_|_____|_  |_|_|___|
                          |___|        
        Now installing BinSync...
        Please input decompiler/debugger install paths as prompted. Enter nothing to either use
        the default install path if one exists, or to skip.
        """))

    def install_ida(self, path=None):
        ida_plugin_path = super().install_ida(path=path)
        if ida_plugin_path is None:
            return None

        src_ida_binsync_py = self.plugins_path.joinpath("ida_binsync.py")
        dst_ida_binsync_py = ida_plugin_path.joinpath("ida_binsync.py")
        self.link_or_copy(src_ida_binsync_py, dst_ida_binsync_py)
        return dst_ida_binsync_py

    def install_angr(self, path=None):
        angr_plugin_path = super().install_angr(path=path)
        if angr_plugin_path is None:
            return None

        src_angr_binsync_pkg = self.plugins_path.joinpath("angr_binsync")
        dst_angr_binsync_pkg = angr_plugin_path.joinpath("angr_binsync")
        self.link_or_copy(src_angr_binsync_pkg, dst_angr_binsync_pkg, is_dir=True)
        return dst_angr_binsync_pkg

    def install_ghidra(self, path=None):
        ghidra_path = super().install_ghidra(path=path)
        if ghidra_path is None:
            return None

        src_ghidra_binsync_pkg = self.plugins_path.joinpath("ghidra_binsync")
        src_vendored = src_ghidra_binsync_pkg.joinpath("binsync_vendored")
        src_script = src_vendored.joinpath("ghidra_binsync.py")

        dst_ghidra_binsync_pkg = ghidra_path.joinpath("binsync_vendored")
        dst_ghidra_script = ghidra_path.joinpath("ghidra_binsync.py")

        self.link_or_copy(src_vendored, dst_ghidra_binsync_pkg, is_dir=True)
        self.link_or_copy(src_script, dst_ghidra_script)
        return ghidra_path

    def install_binja(self, path=None):
        binja_plugin_path = super().install_binja(path=path)
        if binja_plugin_path is None:
            return None

        src_path = self.plugins_path.joinpath("binja_binsync")
        dst_path = binja_plugin_path.joinpath("binja_binsync")
        self.link_or_copy(src_path, dst_path, is_dir=True)
        return binja_plugin_path
