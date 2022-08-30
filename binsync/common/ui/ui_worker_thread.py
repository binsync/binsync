import time
from binsync.common.ui.qt_objects import QObject, Signal, Slot
import binsync.common.controller as bsc
import logging

l = logging.getLogger(name=__name__)


class BinSyncUIWorker(QObject):
    def __init__(self, controller: bsc.BinSyncController, loop_cooldown):
        super().__init__()
        self.controller = controller
        self._run_updater_threads = True
        self.loop_cooldown = loop_cooldown
        self._last_reload = None
        self.reload_time = 10

    def stop(self):
        self._run_updater_threads = False

    def run(self):
        while self._run_updater_threads:
            time.sleep(self.loop_cooldown)
            if not self.controller.headless:
                # update context knowledge every loop iteration
                if self.controller.ctx_change_callback:
                    self.controller._check_and_notify_ctx()

                # update the control panel with new info every self.reload_time seconds
                if self._last_reload is None or \
                        time.time() - self._last_reload > self.reload_time:
                    self._last_reload = time.time()
                    self.controller._update_ui()
