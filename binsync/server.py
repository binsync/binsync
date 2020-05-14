import rpyc


class MainDatabase:
    def __init__(self):
        self.users = {}
        self.dbs = {}


class MainService(rpyc.Service):
    """
    The main service class.
    """

    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        pass

    def exposed_get_users(self, db=None):
        """
        Get all available users across all databases.

        :param str db:  The identifier for DB.
        :return:        A list of user objects.
        :rtype:         list
        """
        return []

    def exposed_get_all_function_metadata(self, db, user, version=None):
        """
        Get the metadata of all functions specified by db+user+version. @version = None retrieves the latest version.

        :param str db:      The DB identifier.
        :param str user:    The user identifier.
        :param str version: The version.
        :return:            A list of function metadata objects.
        :rtype:             list
        """
        return []


def main():
    from rpyc.utils.server import ThreadedServer

    t = ThreadedServer(MainService, port=51200)
    t.start()


if __name__ == "__main__":
    main()
