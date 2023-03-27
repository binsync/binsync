import datetime
import logging

from binsync.common.ui.qt_objects import (
    QFrame,
    QWidget,
    QScrollArea,
    QSizePolicy,
    Qt,
    QPropertyAnimation,
    QAbstractAnimation,
    QToolButton,
    QParallelAnimationGroup,
    Qt,
    QTableWidgetItem,
    QObject,
    QVBoxLayout
)
import datetime
from binsync.core.scheduler import Scheduler
import logging

l = logging.getLogger(__name__)


class QCollapsibleBox(QWidget):
    def __init__(self, title="", parent=None):
        super(QCollapsibleBox, self).__init__(parent)

        self.toggle_button = QToolButton(
            text=title, checkable=True, checked=False
        )
        self.toggle_button.setStyleSheet("QToolButton { border: none; }")
        self.toggle_button.setToolButtonStyle(
            Qt.ToolButtonTextBesideIcon
        )
        self.toggle_button.setArrowType(Qt.RightArrow)
        self.toggle_button.pressed.connect(self.on_pressed)

        self.toggle_animation = QParallelAnimationGroup(self)

        self.content_area = QScrollArea(
            maximumHeight=0, minimumHeight=0
        )
        self.content_area.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Fixed
        )
        self.content_area.setFrameShape(QFrame.NoFrame)

        lay = QVBoxLayout(self)
        lay.setSpacing(0)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.toggle_button)
        lay.addWidget(self.content_area)

        self.toggle_animation.addAnimation(
            QPropertyAnimation(self, b"minimumHeight")
        )
        self.toggle_animation.addAnimation(
            QPropertyAnimation(self, b"maximumHeight")
        )
        self.toggle_animation.addAnimation(
            QPropertyAnimation(self.content_area, b"maximumHeight")
        )

    def on_pressed(self):
        checked = self.toggle_button.isChecked()
        self.toggle_button.setArrowType(
            Qt.DownArrow if not checked else Qt.RightArrow
        )
        self.toggle_animation.setDirection(
            QAbstractAnimation.Forward
            if not checked
            else QAbstractAnimation.Backward
        )
        self.toggle_animation.start()

    def setContentLayout(self, layout):
        lay = self.content_area.layout()
        del lay
        self.content_area.setLayout(layout)
        collapsed_height = (
                self.sizeHint().height() - self.content_area.maximumHeight()
        )
        content_height = layout.sizeHint().height()
        for i in range(self.toggle_animation.animationCount()):
            animation = self.toggle_animation.animationAt(i)
            animation.setDuration(500)
            animation.setStartValue(collapsed_height)
            animation.setEndValue(collapsed_height + content_height)

        content_animation = self.toggle_animation.animationAt(
            self.toggle_animation.animationCount() - 1
        )
        content_animation.setDuration(500)
        content_animation.setStartValue(0)
        content_animation.setEndValue(content_height)


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

