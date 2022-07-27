import xmlrpc.client


class BSBridgeClient:
    def __init__(self, host="localhost", port=9466):
        self.host = host
        self.port = port

        self.server = None

    #
    # Server Ops
    #

    @property
    def connected(self):
        return True if self.server else False

    def connect(self, host=None, port=None) -> bool:
        """
        Connects to the remote decompiler.
        """
        host = host or self.host
        port = port or self.port

        # create a server connection and test it
        try:
            self.server = xmlrpc.client.ServerProxy(f"http://{host}:{port}")
            self.server.ping()
        except (ConnectionRefusedError, AttributeError) as e:
            self.server = None
            return False

        return True
    
    def set_controller_status(self, status):
        self.server.set_controller_status(status)
