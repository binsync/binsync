import ghidra_bridge
import time


class GhidraAPIWrapper:
    def __init__(self, controller, connection_timeout=10):
        self._controller = controller
        self._connection_timeout = connection_timeout

        self._ghidra_bridge = None
        self._ghidra_bridge_attrs = {}
        self.imports = {}

        self.connected = self._connect_ghidra_bridge()
        if not self.connected:
            return

        # dynamically import needed modules
        self._do_init_imports()

    def __getattr__(self, item):
        if item in self._ghidra_bridge_attrs:
            return self._ghidra_bridge_attrs[item]
        else:
            return self.__getattribute__(item)

    def _do_init_imports(self):
        init_modules = [
            "ghidra.app.decompiler",
            "ghidra.framework.model"
        ]
        for module_name in init_modules:
            self.imports[module_name] = self._ghidra_bridge.remote_import(module_name)

    def _connect_ghidra_bridge(self):
        start_time = time.time()
        successful = False
        while time.time() - start_time < self._connection_timeout:
            try:
                self._ghidra_bridge = ghidra_bridge.GhidraBridge(namespace=self._ghidra_bridge_attrs, interactive_mode=True)
                successful = True
            except ConnectionError:
                time.sleep(1)

            if successful:
                break

        return successful
