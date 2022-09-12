# pylint: disable=missing-class-docstring
import glob
import os
import platform
import shutil
import subprocess
import sys
from distutils.command.build import build as st_build
from distutils.util import get_platform

import pkg_resources
from setuptools import Command, setup
from setuptools.command.develop import develop as st_develop


def _copy_decomp_plugins():
    shutil.rmtree("binsync/plugins", ignore_errors=True)
    shutil.copytree("plugins", "binsync/plugins")


def _clean_plugins():
    shutil.rmtree("plugins")


class build(st_build):
    def run(self, *args):
        self.execute(_copy_decomp_plugins, (), msg="Copying binsync plugins")
        super().run(*args)


class clean_plugins(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.execute(_clean_plugins, (), msg="Cleaning angr_native")


class develop(st_develop):
    def run(self):
        self.run_command("build")
        super().run()


cmdclass = {
    "build": build,
    "clean_plugins": clean_plugins,
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