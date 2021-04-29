import uuid


class User:
    """
    :ivar str name: Name of the user
    :ivar str uid:  Internal user ID in the form of uuid.
    :ivar int last_push_time: Last pushed time of user.
    :ivar int last_push_func: Last pushed function address of user.
    """

    def __init__(self, name, uid=None, client=None):
        self.name = name
        self.uid = uid if uid is not None else uuid.uuid4()
        self.client = client
        self.last_push_time = 0
        self.last_push_func = 0

    @classmethod
    def from_metadata(cls, metadata):
        u = cls(
            metadata["user"],
            uid=metadata.get("uid", None),
            client=metadata.get("client", None),
            last_push_time=metadata.get("last_push_time", None),
            last_push_func=metadata.get("last_push_func", None)
        )
        return u
