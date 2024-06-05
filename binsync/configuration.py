import pathlib
import os
import logging

import toml

from libbs.configuration import BSConfig

BS_CONFIG_POSTFIX = "bsconf"
BS_GLOBAL_CONFIG_FILENAME = f".global.{BS_CONFIG_POSTFIX}"

l = logging.getLogger(__name__)

# TODO: Add file locking to prevent simultaneous file accessing
class BinSyncBSConfig(BSConfig):
    __slots__ = BSConfig.__slots__ + (
        "project_data",
        "recent_bs_projects",
    )

    def __init__(self,
                 save_location=None,
                 recent_bs_projects=None,
                 ):
        super().__init__(save_location)

        self.save_location = self.save_location / f"{__class__.__name__}.toml"
        self.recent_bs_projects = recent_bs_projects
        self.project_data = {}

    def save_project_data(self, binary_path, user=None, repo_path=None, remote=None, table_coloring_window=None, log_level=None, merge_level=None):
        project_data = {}
        binary_name = pathlib.Path(binary_path).name
        project_data["binary_name"] = binary_name
        project_data["user"] = user
        project_data["repo_path"] = repo_path
        project_data["remote"] = remote
        project_data["table_coloring_window"] = table_coloring_window
        project_data["log_level"] = log_level
        project_data["merge_level"] = merge_level

        self.project_data[binary_name] = project_data
    def add_recent_project_path(self, path, user):
        if self.recent_bs_projects is None:
            self.recent_bs_projects = []

        self.recent_bs_projects.insert(0, f"{path}:{user}")
        self.recent_bs_projects = self.recent_bs_projects[0:5]
