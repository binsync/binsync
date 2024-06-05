import pathlib
import os
import logging

import toml

from libbs.configuration import BSConfig

BS_CONFIG_POSTFIX = "bsconf"
BS_GLOBAL_CONFIG_FILENAME = f".global.{BS_CONFIG_POSTFIX}"

l = logging.getLogger(__name__)


class Config:
    __slots__ = (
        "path",
    )

    def __init__(self, path):
        self.path = path

    def save(self):
        self.path = pathlib.Path(self.path).expanduser().absolute()
        if not self.path.parent.exists():
            return None

        dump_dict = {}
        for attr in self.__slots__:
            attr_val = getattr(self, attr)
            if isinstance(attr_val, pathlib.Path):
                attr_val = str(attr_val)

            dump_dict[attr] = attr_val

        with open(self.path, "w") as fp:
            toml.dump(dump_dict, fp)

        return self.path

    def load(self):
        self.path = pathlib.Path(self.path).expanduser().absolute()
        if not self.path.exists():
            return None

        with open(self.path, "r") as fp:
            load_dict = toml.load(fp)

        for attr in self.__slots__:
            setattr(self, attr, load_dict.get(attr, None))

        return self

    @classmethod
    def load_from_file(cls, path):
        conf = cls(path)
        return conf.load()

    @classmethod
    def update_or_make(cls, path, **attrs_to_update):
        path = pathlib.Path(cls.correct_path(path)).expanduser().absolute()
        # find or create a new config
        conf = cls.load_from_file(path) if path.exists() \
            else cls(path)

        # update every value in the Config
        for attr, val in attrs_to_update.items():
            if attr in conf.__slots__:
                setattr(conf, attr, val)

        conf.save()
        return conf

    @classmethod
    def correct_path(cls, path):
        return path


class ProjectConfig(Config):
    __slots__ = Config.__slots__ + (
        "binary_name",
        "user",
        "repo_path",
        "remote",
        "table_coloring_window",
        "log_level",
        "merge_level"
    )

    def __init__(self,
                 binary_path,
                 user=None,
                 repo_path=None,
                 remote=None,
                 table_coloring_window=None,
                 log_level=None,
                 merge_level=None,
                 ):
        super(ProjectConfig, self).__init__(self.correct_path(binary_path))

        self.binary_name = pathlib.Path(binary_path).name
        self.user = user
        self.repo_path = repo_path
        self.remote = remote
        self.table_coloring_window = table_coloring_window
        self.log_level = log_level
        self.merge_level = merge_level

    @classmethod
    def correct_path(cls, binary_path):
        # example config: /path/to/fauxware_files/.fauxware.bsconf
        binary_path = pathlib.Path(binary_path)
        config_name = pathlib.Path(f".{binary_path.name}.{BS_CONFIG_POSTFIX}")
        config_dir = binary_path.parent
        return str(config_dir.joinpath(config_name))


class GlobalConfig(Config):
    __slots__ = Config.__slots__ + (
        "recent_bs_projects",
        "ida_path",
        "ghidra_path",
        "angr_path",
        "binja_path",
        "gdb_path",
    )

    def __init__(self,
                 path,
                 recent_bs_projects=None,
                 ida_path=None,
                 ghidra_path=None,
                 angr_path=None,
                 binja_path=None,
                 gdb_path=None,
                 ):
        super(GlobalConfig, self).__init__(GlobalConfig.correct_path(path))

        self.recent_bs_projects = recent_bs_projects or []
        self.angr_path = angr_path
        self.ida_path = ida_path
        self.ghidra_path = ghidra_path
        self.binja_path = binja_path
        self.gdb_path = gdb_path

    @classmethod
    def correct_path(cls, path):
        if path is None:
            path = os.getenv("HOME") or "~/"
        path = pathlib.Path(path).expanduser().absolute()

        if path.is_dir():
            path = path.joinpath(BS_GLOBAL_CONFIG_FILENAME)
        elif path.name != BS_GLOBAL_CONFIG_FILENAME:
            l.warning("")
            path = path.parent.joinpath(BS_GLOBAL_CONFIG_FILENAME)

        return path

    def add_recent_project_path(self, path, user):
        if self.recent_bs_projects is None:
            self.recent_bs_projects = []

        self.recent_bs_projects.insert(0, f"{path}:{user}")
        # only save the last 5 projects
        self.recent_bs_projects = self.recent_bs_projects[0:5]
