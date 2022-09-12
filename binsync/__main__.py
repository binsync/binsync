import argparse
import sys
import logging
from pathlib import Path
import importlib
import pkg_resources

import binsync

l = logging.getLogger(__name__)


def execute_plugin_entry(plugin_name):
    plugins_path = Path(
        pkg_resources.resource_filename("binsync", f"plugins")
    )
    if not plugins_path.exists():
        l.error("Known plugins path does not exist, which means BinSync did not install correctly!")
        return False

    sys.path.insert(1, str(plugins_path))
    plugin = importlib.import_module(f"{plugin_name}_binsync")
    l.debug(f"Executing {plugin_name} plugin...")
    return plugin.start()


def main():
    parser = argparse.ArgumentParser(description="BinSync command line util")
    parser.add_argument(
        "-p", "--run-plugin", help="Execute BinSync decompiler plugin by command line, results may vary!"
    )

    args = parser.parse_args()
    plugin_to_run = args.run_plugin

    if plugin_to_run:
        return execute_plugin_entry(plugin_to_run)


if __name__ == "__main__":
    main()
