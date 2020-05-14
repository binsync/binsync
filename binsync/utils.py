import sys


def is_py2():
    return sys.version_info.major == 2


def is_py3():
    return sys.version_info.major == 3
