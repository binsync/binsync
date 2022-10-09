# pylint: disable=missing-class-docstring
import os
import platform
import shutil
from pathlib import Path
import sys
from distutils.command.build import build as st_build
from distutils.util import get_platform

from setuptools import Command, setup
from setuptools.command.develop import develop as st_develop


def _copy_decomp_plugins():
    local_plugins = Path("plugins").absolute()
    pip_e_plugins = Path("binsync").joinpath("plugins").absolute()

    # clean the install location of symlink or folder
    shutil.rmtree(pip_e_plugins, ignore_errors=True)
    try:
        os.unlink(pip_e_plugins)
    except:
        pass

    # first attempt a symlink, if it works, exit early
    try:
        os.symlink(local_plugins, pip_e_plugins, target_is_directory=True)
        return
    except:
        pass

    # copy if symlinking is not available on target system
    shutil.copytree("plugins", "binsync/plugins")


class develop(st_develop):
    def run(self, *args):
        self.execute(_copy_decomp_plugins, (), msg="Linking or copying local plugins folder")
        super().run(*args)


cmdclass = {
    "develop": develop,
}

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    sys.argv.append('--plat-name')
    name = get_platform()
    if 'linux' in name:
        sys.argv.append('manylinux2014_' + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace('.', '_').replace('-', '_'))

setup(cmdclass=cmdclass)
