import uuid


class User:
    """
    :ivar str name: Name of the user
    :ivar str uid:  Internal user ID in the form of uuid.
    :ivar int push_time: Last push time of user.
    :ivar int last_push_func: Last function address modified pushed.
    """

    def __init__(self, name, uid=None, client=None,
                 last_push_time=-1, last_push_artifact=-1, last_push_artifact_type=1, last_commit_msg=None):
        self.name = name
        self.uid = uid if uid is not None else uuid.uuid4()
        self.client = client
        self.last_push_time = last_push_time
        self.last_push_artifact = last_push_artifact
        self.last_push_artifact_type = last_push_artifact_type
        self.last_commit_msg = last_commit_msg

    @classmethod
    def from_metadata(cls, metadata):
        u = cls(
            metadata["user"],
            uid=metadata.get("uid", None),
            client=metadata.get("client", None),
            last_push_time=metadata.get("last_push_time", -1),
            last_push_artifact=metadata.get("last_push_artifact", -1),
            last_push_artifact_type=metadata.get("last_push_artifact_type", -1),
            last_commit_msg=metadata.get("last_commit_msg", None)
        )
        return u

    def copy(self):
        return User(
            self.name,
            uid=self.uid,
            client=self.client,
            last_push_time=self.last_push_time,
            last_push_artifact=self.last_push_artifact,
            last_push_artifact_type=self.last_push_artifact_type,
            last_commit_msg=self.last_commit_msg
        )