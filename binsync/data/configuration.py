import pathlib
import os
import toml
import logging

l = logging.getLogger(__name__)
BINSYNC_CONFIG_POSTFIX = "bsconf"


class Config:
    __slots__ = (
        "path",
    )

    def __init__(self, path):
        self.path = path

    def save(self):
        l.debug(f"Saving Configuration File: '{self.path}'")
        dump_dict = {
            attr: getattr(self, attr) for attr in self.__slots__
        }

        with open(self.path, "w") as fp:
            toml.dump(dump_dict, fp)

        return self.path

    def load(self):
        path = pathlib.Path(self.path)
        if not path.exists():
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


class ProjectConfig(Config):
    __slots__ = Config.__slots__ + (
        "binary_name",
        "user",
        "repo_path",
        "remote",
        "table_coloring_window",
        "sync_level",
        "log_level"
    )

    def __init__(self,
                 binary_path,
                 user=None,
                 repo_path=None,
                 remote=None,
                 table_coloring_window=None,
                 sync_level=None,
                 log_level=None
                 ):
        super(ProjectConfig, self).__init__(self._correct_path(binary_path))

        self.binary_name = pathlib.Path(binary_path).name
        self.user = user
        self.repo_path = repo_path
        self.remote = remote
        self.table_coloring_window = table_coloring_window
        self.sync_level = sync_level
        self.log_level = log_level

    def _correct_path(self, binary_path):
        # example config: /path/to/fauxware_files/.fauxware.bsconf
        binary_path = pathlib.Path(binary_path)
        config_name = pathlib.Path(f".{binary_path.name}.{BINSYNC_CONFIG_POSTFIX}")
        config_dir = binary_path.parent
        return str(config_dir.joinpath(config_name))


class GlobalConfig(Config):
    __slots__ = Config.__slots__ + (
        "last_bs_repo_path",
    )

    def __init__(self,
                 path,
                 last_bs_repo_path=None
                 ):
        super(GlobalConfig, self).__init__(self._correct_path(path))

        self.last_bs_repo_path = last_bs_repo_path

    def _correct_path(self, path):
        if path is None:
            path = os.getenv("HOME") or "."

        path = pathlib.Path(path)
        name = pathlib.Path(f".global.{BINSYNC_CONFIG_POSTFIX}")
        return str(path.joinpath(name))
