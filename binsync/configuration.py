import pathlib
import os
import logging
import itertools
import toml

from hashlib import sha256
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
    def __init__(self, binary_path, user=None, repo_path=None, remote=None):
        binary_name = pathlib.Path(binary_path).name
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
        proj_data = cls(data['binary_path'])
        proj_data.__setstate__(data)
        return proj_data


# TODO: Add file locking to prevent simultaneous file accesses
class BinSyncBSConfig(BSConfig):
    __slots__ = BSConfig.__slots__ + (
        "project_data",
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
        self.project_data = {}

    def save_project_data(self, binary_path, user=None, repo_path=None, remote=None):
        project_data = {"binary_path": binary_path, "user": user, "repo_path": repo_path, "remote": remote}
        projectData = ProjectData.get_from_state(project_data)
        self.add_recent_project_data(binary_path, projectData)
    def add_recent_project_data(self, binary_path, projectData):
        if self.recent_projects is None:
            self.recent_projects = OrderedDict()

        binary_hash = _hashfile(binary_path)
        if binary_hash not in self.recent_projects.keys():
            self.recent_projects.update({binary_hash: []})
            self.recent_projects.move_to_end(binary_hash, last=False)

        self.recent_projects[binary_hash].insert(0, projectData.__getstate__)
        self.recent_projects[binary_hash] = self.recent_projects[binary_hash][0:5]
        self.recent_projects = OrderedDict(itertools.islice(self.recent_projects.items(), 10))

def _hashfile(path):
    with open(path, 'rb') as f:
        data = f.read()
    return sha256(data).digest().hex()