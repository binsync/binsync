import argparse
import sys
import logging
from pathlib import Path
import importlib
import pkg_resources

from binsync.installer import BinSyncInstaller

l = logging.getLogger(__name__)


def run_plugin(plugin_name):
    plugins_path = Path(
        pkg_resources.resource_filename("binsync", f"decompiler_stubs")
    )
    if not plugins_path.exists():
        l.error("Known plugins path does not exist, which means BinSync did not install correctly!")
        return False

    sys.path.insert(1, str(plugins_path))
    plugin = importlib.import_module(f"{plugin_name}_binsync")
    l.debug(f"Executing {plugin_name} plugin...")
    return plugin.start()


def install():
    BinSyncInstaller().install()


def install_angr(path):
    if not path.exists():
        print("Path does not exist, please rerun with a valid path.")
        return

    installer = BinSyncInstaller()
    installer.install_angr(path=path)


def main():
    parser = argparse.ArgumentParser(
            description="""
            The BinSync Command Line Util. This is the script interface to BinSync that allows you to
            do a variety of things that are independent of running in a decompiler like installing, 
            testing plugin code, and merging databases.
            """,
            epilog="""
            Examples:
            binsync --install
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install the BinSync core to supported decompilers as plugins. This option will start an interactive
        prompt asking for install paths for all supported decompilers. Each install path is optional and 
        will be skipped if not path is provided during install. 
        """
    )
    parser.add_argument(
        "--install-angr-only", type=Path, help="""
        Does a non-interactive install for angr only from the provided path.
        """
    )
    parser.add_argument(
        "--run-plugin", help="""
        Execute BinSync decompiler plugin by command line. This is a developer option.
        """
    )

    args = parser.parse_args()

    if args.install:
        install()

    if args.install_angr_only:
        path = Path(args.install_angr_only).expanduser().absolute()
        install_angr(path)


    if args.run_plugin:
        return run_plugin(args.run_plugin)


if __name__ == "__main__":
    main()
