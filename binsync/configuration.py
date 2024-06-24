import pathlib
import logging
import itertools

from hashlib import md5
from typing import Optional, Dict

from libbs.configuration import BSConfig

l = logging.getLogger(__name__)
max_recent_projects = 5
max_saved_binaries = 10

class ProjectData:
    __slots__ = (
        "binary_name",
        "user",
        "repo_path",
        "remote",
    )

    def __init__(self,
                 binary_name: str,
                 user: Optional[str] = None,
                 repo_path: Optional[str] = None,
                 remote: Optional[str] = None
                 ):
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


class BinSyncBSConfig(BSConfig):
    __slots__ = BSConfig.__slots__ + (
        "recent_projects",
        "table_coloring_window",
        "log_level",
        "merge_level",
    )

    def __init__(self,
                 save_location: Optional[pathlib.Path] = None,
                 recent_projects: Optional[Dict] = None,
                 table_coloring_window: Optional[int] = None,
                 log_level: Optional[str] = None,
                 merge_level: Optional[int] = None
                 ):
        super().__init__(save_location)

        self.save_location = self.save_location / f"{__class__.__name__}.toml"
        self.table_coloring_window = table_coloring_window
        self.log_level = log_level
        self.merge_level = merge_level
        self.recent_projects = recent_projects

    def save_project_data(self, binary_path, user=None, repo_path=None, remote=None):
        project_data = {"binary_name": pathlib.Path(binary_path).name, "user": user, "repo_path": str(repo_path),
                        "remote": remote}
        projectData = ProjectData.get_from_state(project_data)
        binary_hash = _hashfile(binary_path)
        self.add_recent_project_data(binary_hash, projectData)

    def add_recent_project_data(self, binary_hash, projectData):
        if self.recent_projects is None:
            self.recent_projects = {}

        if binary_hash not in self.recent_projects.keys():
            self.recent_projects = _dict_insert(self.recent_projects, binary_hash, [])

        if {k: v for k, v in projectData.__getstate__().items() if v is not None} not in self.recent_projects[
            binary_hash]:
            self.recent_projects[binary_hash].insert(0, projectData.__getstate__())

        self.recent_projects[binary_hash] = self.recent_projects[binary_hash][0:max_recent_projects]
        self.recent_projects = dict(itertools.islice(self.recent_projects.items(), max_saved_binaries))


def _dict_insert(dictionary, key, value):
    new_dict = {key: value}
    for k, v in dictionary.items():
        new_dict[k] = v
    return new_dict


def _hashfile(path):
    with open(path, 'rb') as f:
        data = f.read()
    return md5(data).digest().hex()
