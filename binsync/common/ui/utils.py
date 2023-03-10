import datetime
import logging

from binsync.common.ui.qt_objects import Qt, QTableWidgetItem, QObject
import datetime
from binsync.core.scheduler import Scheduler
import logging

l = logging.getLogger(__name__)


class QNumericItem(QTableWidgetItem):
    def __lt__(self, other):
        if self.data(Qt.UserRole) is None:
            return True
        elif other.data(Qt.UserRole) is None:
            return False

        return self.data(Qt.UserRole) < other.data(Qt.UserRole)


class BSUIScheduler(QObject, Scheduler):
    """
    Just like the normal Schedule, but follows the PyQT (and PySide) for Objects running
    in another thread. Only useful for scheduling UI jobs.
    """
    def __init__(self, sleep_interval=0.05):
        QObject.__init__(self)
        Scheduler.__init__(self, sleep_interval=sleep_interval)
        self._work = True

    def stop(self):
        self._work = False

    def run(self):
        self._worker_thread()


def friendly_datetime(time_before):
    # convert fro unix
    if isinstance(time_before, int):
        if time_before == -1:
            return ""
        dt = datetime.datetime.fromtimestamp(time_before, tz=datetime.timezone.utc)
    elif isinstance(time_before, datetime.datetime):
        dt = time_before
    else:
        return ""

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if dt <= now:
        diff = now - dt
        ago = True
    else:
        diff = dt - now
        ago = False
    diff_days = diff.days
    diff_sec = diff.seconds

    if diff_days >= 1:
        s = "%d days" % diff_days
    elif diff_sec >= 60 * 60:
        s = "%d hours" % int(diff_sec / 60 / 60)
    elif diff_sec >= 60:
        s = "%d minutes" % int(diff_sec / 60)
    else:
        s = "%d seconds" % diff_sec

    s += " ago" if ago else " in the future"
    return s


def menu_stub(menu):
    return menu

