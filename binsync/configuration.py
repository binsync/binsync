import pathlib
import os
import logging
import itertools
import toml

from hashlib import md5
from collections import OrderedDict
from libbs.configuration import BSConfig

l = logging.getLogger(__name__)


class ProjectData:
    __slots__ = (
        "binary_name",
        "user",
        "repo_path",
        "remote",
    )

    def __init__(self, binary_name, user=None, repo_path=None, remote=None):
        self.binary_name = binary_name
        self.user = user
        self.repo_path = repo_path
        self.remote = remote

    def __setstate__(self, data):
        for k in self.__slots__:
            if k in data:
                setattr(self, k, data[k])

    def __getstate__(self):
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    @classmethod
    def get_from_state(cls, data):
        proj_data = cls(data['binary_name'])
        proj_data.__setstate__(data)
        return proj_data


# TODO: Add file locking to prevent simultaneous file accesses
class BinSyncBSConfig(BSConfig):
    __slots__ = BSConfig.__slots__ + (
        "recent_projects",
        "table_coloring_window",
        "log_level",
        "merge_level",
    )

    def __init__(self,
                 save_location=None,
                 recent_projects=None,
                 table_coloring_window=None,
                 log_level=None,
                 merge_level=None
                 ):
        super().__init__(save_location)

        self.save_location = self.save_location / f"{__class__.__name__}.toml"
        self.table_coloring_window = table_coloring_window
        self.log_level = log_level
        self.merge_level = merge_level
        self.recent_projects = recent_projects

    def save_project_data(self, binary_path, user=None, repo_path=None, remote=None):
        project_data = {"binary_name": pathlib.Path(binary_path).name, "user": user, "repo_path": repo_path, "remote": remote}
        projectData = ProjectData.get_from_state(project_data)
        binary_hash = _hashfile(binary_path)
        self.add_recent_project_data(binary_hash, projectData)

    def add_recent_project_data(self, binary_hash, projectData):
        if self.recent_projects is None:
            self.recent_projects = {}

        if binary_hash not in self.recent_projects.keys():
            self.recent_projects = _dict_insert(self.recent_projects, binary_hash, [])

        if projectData.__getstate__() not in self.recent_projects[binary_hash]:
            self.recent_projects[binary_hash].insert(0, projectData.__getstate__())

        self.recent_projects[binary_hash] = self.recent_projects[binary_hash][0:5]
        self.recent_projects = dict(itertools.islice(self.recent_projects.items(), 10))


def _dict_insert(dictionary, key, value):
    new_dict = {key: value}
    for k, v in dictionary.items():
        new_dict[k] = v
    return new_dict

def _hashfile(path):
    with open(path, 'rb') as f:
        data = f.read()
    return md5(data).digest().hex()
