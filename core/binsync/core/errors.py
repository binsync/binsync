class BaseError(Exception):
    pass


class MetadataNotFoundError(BaseError):
    pass


class ExternalUserCommitError(BaseError):
    pass
