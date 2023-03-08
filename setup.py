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


def _copy_decomp_decompiler_stubs():
    local_decompiler_stubs = Path("decompiler_stubs").absolute()
    pip_e_decompiler_stubs = Path("binsync").joinpath("decompiler_stubs").absolute()

    # clean the install location of symlink or folder
    shutil.rmtree(pip_e_decompiler_stubs, ignore_errors=True)
    try:
        os.unlink(pip_e_decompiler_stubs)
    except:
        pass

    # first attempt a symlink, if it works, exit early
    try:
        os.symlink(local_decompiler_stubs, pip_e_decompiler_stubs, target_is_directory=True)
        return
    except:
        pass

    # copy if symlinking is not available on target system
    shutil.copytree("decompiler_stubs", "binsync/decompiler_stubs")


class build(st_build):
    def run(self, *args):
        self.execute(_copy_decomp_decompiler_stubs, (), msg="Copying binsync decompiler_stubs")
        super().run(*args)


class develop(st_develop):
    def run(self, *args):
        self.execute(_copy_decomp_decompiler_stubs, (), msg="Linking or copying local decompiler_stubs folder")
        super().run(*args)


cmdclass = {
    "build": build,
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
