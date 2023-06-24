import time
import logging

import ghidra_bridge

l = logging.getLogger(__name__)

class GhidraAPIWrapper:
    def __init__(self, controller, connection_timeout=10):
        self._controller = controller
        self._connection_timeout = connection_timeout

        self._ghidra_bridge = None
        self._ghidra_bridge_attrs = {}
        self._imports = {}

        self.connected = self._connect_ghidra_bridge()
        if not self.connected:
            return

    def __getattr__(self, item):
        if item in self._ghidra_bridge_attrs:
            return self._ghidra_bridge_attrs[item]
        else:
            return self.__getattribute__(item)

    def import_module_object(self, module_name: str, obj_name: str):
        module = self.import_module(module_name)
        try:
            module_obj = getattr(module, obj_name)
        except AttributeError:
            l.critical(f"Failed to import {module}.{obj_name}")
            module_obj = None

        return module_obj

    def import_module(self, module_name: str):
        if module_name not in self._imports:
            self._imports[module_name] = self._ghidra_bridge.remote_import(module_name)

        return self._imports[module_name]

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
