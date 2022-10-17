import os
import readline
from pathlib import Path
import textwrap
import pkg_resources
import shutil
from urllib.request import urlretrieve


class Installer:
    decompilers = (
        "ida",
        "binja",
        "ghidra",
        "angr"
    )

    def __init__(self):
        readline.set_completer_delims(' \t\n=')
        readline.parse_and_bind("tab: complete")

    def install(self):
        self.display_prologue()
        try:
            self.install_all_decompilers()
        except KeyboardInterrupt:
            print("Stopping Install...")
        self.display_epilogue()

    def display_prologue(self):
        pass

    def display_epilogue(self):
        pass

    @staticmethod
    def ask_path(question):
        filepath = input(question)
        if not filepath:
            return None

        filepath = Path(filepath)
        if not filepath.absolute().exists():
            return None

        return filepath.absolute()

    @staticmethod
    def link_or_copy(src, dst, is_dir=False):
        # clean the install location
        shutil.rmtree(dst, ignore_errors=True)
        try:
            os.unlink(dst)
        except:
            pass

        # first attempt a symlink, if it works, exit early
        try:
            os.symlink(src, dst, target_is_directory=is_dir)
            return
        except:
            pass

        # copy if symlinking is not available on target system
        if is_dir:
            shutil.copytree(src, dst)
        else:
            shutil.copy(src, dst)

    def install_all_decompilers(self):
        for decompiler in self.decompilers:
            try:
                installer = getattr(self, f"install_{decompiler}")
            except AttributeError:
                continue

            installer()

    def install_ida(self):
        ida_plugin_path = Path("~/").joinpath(".idapro").joinpath("plugins").expanduser()
        default_str = f" [default = {ida_plugin_path}]"
        if not ida_plugin_path.exists():
            ida_plugin_path = None
            default_str = ""

        path = self.ask_path(f"IDA Plugins Path{default_str}:\n")
        if not path:
            if not ida_plugin_path:
                return None

            path = ida_plugin_path

        if not path.absolute().exists():
            return None

        return path

    def install_ghidra(self):
        path = self.ask_path("Ghidra Install Path:\n")
        if not path:
            return None

        path = path.joinpath("Extensions").joinpath("Ghidra")
        if not path.absolute().exists():
            return None

        return path

    def install_binja(self):
        binja_install_path = Path("~/").joinpath(".binaryninja").joinpath("plugins").expanduser()
        default_str = f" [default = {binja_install_path}]"
        if not binja_install_path.exists():
            binja_install_path = None
            default_str = ""

        path = self.ask_path(f"Binary Ninja Plugins Path{default_str}:\n")
        if not path:
            if not binja_install_path:
                return None

            path = binja_install_path

        return path

    def install_angr(self):
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

        # use the default if possible
        path = self.ask_path(f"angr-management Install Path{default_str}:\n")
        if not path:
            if not angr_install_path:
                return None

            path = angr_install_path

        path = path.joinpath("plugins")
        if not path.absolute().exists():
            return None

        return path


class BinSyncInstaller(Installer):
    def __init__(self):
        super().__init__()
        self.plugins_path = Path(
            pkg_resources.resource_filename("binsync", f"plugins")
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
        the default install path if one exist, or to skip.
        """))

    def install_ida(self):
        ida_plugin_path = super().install_ida()
        if ida_plugin_path is None:
            return

        src_ida_binsync_pkg = self.plugins_path.joinpath("ida_binsync").joinpath("ida_binsync")
        src_ida_binsync_py = self.plugins_path.joinpath("ida_binsync").joinpath("ida_binsync.py")
        dst_ida_binsync_pkg = ida_plugin_path.joinpath("ida_binsync")
        dst_ida_binsync_py = ida_plugin_path.joinpath("ida_binsync.py")
        self.link_or_copy(src_ida_binsync_pkg, dst_ida_binsync_pkg, is_dir=True)
        self.link_or_copy(src_ida_binsync_py, dst_ida_binsync_py)

    def install_angr(self):
        angr_plugin_path = super().install_angr()
        if angr_plugin_path is None:
            return None

        src_angr_binsync_pkg = self.plugins_path.joinpath("angr_binsync")
        dst_angr_binsync_pkg = angr_plugin_path.joinpath("angr_binsync")
        self.link_or_copy(src_angr_binsync_pkg, dst_angr_binsync_pkg, is_dir=True)

    def install_ghidra(self):
        ghidra_path = super().install_ghidra()
        if ghidra_path is None:
            return None
        
        download_url = "https://github.com/angr/binsync/releases/latest/download/ghidra_10.1.4_PUBLIC_20221009_binsync-ghidra-plugin.zip"
        dst_path = ghidra_path.joinpath("binsync-ghidra-plugin.zip")
        urlretrieve(download_url, dst_path)

    def install_binja(self):
        binja_plugin_path = super().install_binja()
        if binja_plugin_path is None:
            return None

        src_path = self.plugins_path.joinpath("binja_binsync")
        dst_path = binja_plugin_path.joinpath("binja_binsync")
        self.link_or_copy(src_path, dst_path, is_dir=True)
