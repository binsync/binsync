import sys
import os
import subprocess
from urllib.request import urlretrieve

# How to run:
# import urllib; urllib.request.urlretrieve(https://github.com/angr/binsync/blob/master/plugins/ida_binsync/oneliner.py, "oneliner.py"); from oneliner import install; install()


class PlatformType:
    MACOS = "macos"
    LINUX = "linux"
    WINDOWS = "windows"


def find_platform():
    platform = PlatformType.WINDOWS

    if sys.platform == "linux" or sys.platform == "linux2":
        platform = PlatformType.LINUX
    elif sys.platform == "darwin":
        platform = PlatformType.MACOS

    return platform


def plugin_install_binsync(plugins_path):
    github_url_base = "https://github.com/angr/binsync/blob/master/plugins/ida_binsync/"
    ida_binsync_folder = os.path.join(plugins_path, "ida_binsync")

    # install entry point of binsync
    urlretrieve(github_url_base+"ida_binsync.py", os.path.join(plugins_path, "ida_binsync.py"))

    # install ida_binsync/*
    github_url_base += "ida_binsync/"
    files_to_download = ["__init__.py", "compat.py", "controller.py", "hooks.py", "plugin.py"]
    try:
        os.mkdir(ida_binsync_folder)
    except FileExistsError:
        pass
    for f in files_to_download:
        urlretrieve(github_url_base+f, os.path.join(ida_binsync_folder, f))


def pip_install_binsync(python_path):
    subprocess.run([python_path] + "-m pip install binsync".split(" "))


def install():
    # confirm install platform works
    platform = find_platform()
    if platform not in [PlatformType.LINUX, PlatformType.MACOS]:
        raise Exception("Platform is not supported for oneliner install.")

    # find plugin path
    for plugin_path in sys.path:
        if os.path.basename(plugin_path) == "plugins" and "ida" in plugin_path:
            break
    else:
        raise Exception("Unable to find the local plugins folder to install BinSync.")

    # find python executable
    if platform == PlatformType.LINUX:
        python_path = sys.executable
    elif platform == PlatformType.MACOS:
        for lib_path in sys.path:
            basename = os.path.basename(lib_path)
            if basename.startswith("python") and not basename.endswith(".zip"):
                python_path = os.path.join(lib_path, f"../../bin/{basename}")
                if os.path.exists(python_path):
                    break
        else:
            raise Exception("Unable to locate your local python executable. Please use manual install.")

    pip_install_binsync(python_path)
    print("[+] Successfully installed BinSync to IDA pip")
    plugin_install_binsync(plugin_path)
    print("[+] Successfully installed BinSync IDA Plugin into the plugins folder")
    print("[+] Install finished. PLEASE RESTART IDA for plugin to be loaded")





