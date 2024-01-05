import textwrap

from libbs.plugin_installer import LibBSPluginInstaller, PluginInstaller


class BinSyncInstaller(LibBSPluginInstaller):
    def __init__(self):
        super().__init__(targets=PluginInstaller.DECOMPILERS)
        pkg_files = self.find_pkg_files("binsync")
        if pkg_files is None:
            raise RuntimeError("Could not find binsync package files. Please reinstall or report on GitHub.")

        self.plugins_path = pkg_files / "stub_files"

    def display_prologue(self):
        print(textwrap.dedent("""
        Now installing...
         _____ _     _____             
        | __  |_|___|   __|_ _ ___ ___ 
        | __ -| |   |__   | | |   |  _|
        |_____|_|_|_|_____|_  |_|_|___|
                          |___|        
        
        The decompiler-agnostic git-based collaboration tool for reverse engineers.
        """))

    def install_ida(self, path=None, interactive=True):
        ida_plugin_path = super().install_ida(path=path)
        if ida_plugin_path is None:
            return None

        src_ida_binsync_py = self.plugins_path.joinpath("ida_binsync.py")
        dst_ida_binsync_py = ida_plugin_path.joinpath("ida_binsync.py")
        self.link_or_copy(src_ida_binsync_py, dst_ida_binsync_py)
        return ida_plugin_path

    def install_angr(self, path=None, interactive=True):
        angr_plugin_path = super().install_angr(path=path)
        if angr_plugin_path is None:
            return None

        src_angr_binsync_pkg = self.plugins_path.joinpath("angr_binsync")
        dst_angr_binsync_pkg = angr_plugin_path.joinpath("angr_binsync")
        self.link_or_copy(src_angr_binsync_pkg, dst_angr_binsync_pkg, is_dir=True)
        return angr_plugin_path

    def install_ghidra(self, path=None, interactive=True):
        ghidra_path = super().install_ghidra(path=path)
        if ghidra_path is None:
            return None

        src_ghidra_binsync_pkg = self.plugins_path.joinpath("ghidra_binsync")
        src_vendored = src_ghidra_binsync_pkg.joinpath("binsync_vendored")
        src_script = src_ghidra_binsync_pkg.joinpath("ghidra_binsync.py")
        src_script_shutdown = src_ghidra_binsync_pkg.joinpath("ghidra_binsync_shutdown.py")

        dst_ghidra_binsync_pkg = ghidra_path.joinpath("binsync_vendored")
        dst_ghidra_script = ghidra_path.joinpath("ghidra_binsync.py")
        dst_script_shutdown = ghidra_path.joinpath("ghidra_binsync_shutdown.py")

        self.link_or_copy(src_vendored, dst_ghidra_binsync_pkg, is_dir=True)
        self.link_or_copy(src_script, dst_ghidra_script)
        self.link_or_copy(src_script_shutdown, dst_script_shutdown)
        return ghidra_path

    def install_binja(self, path=None, interactive=True):
        binja_plugin_path = super().install_binja(path=path)
        if binja_plugin_path is None:
            return None

        src_path = self.plugins_path.joinpath("binja_binsync")
        dst_path = binja_plugin_path.joinpath("binja_binsync")
        self.link_or_copy(src_path, dst_path, is_dir=True)
        return binja_plugin_path
