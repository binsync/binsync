import uuid


class User:
    """
    :ivar str name: Name of the user
    :ivar str uid:  Internal user ID in the form of uuid.
    """

    def __init__(self, name, uid=None, client=None):
        self.name = name
        self.uid = uid if uid is not None else uuid.uuid4()
        self.client = client

    @classmethod
    def from_metadata(cls, metadata):
        u = cls(
            metadata["user"],
            uid=metadata.get("uid", None),
            client=metadata.get("client", None),
        )
        return u
