from binsync.common.ui.version import ui_version

if ui_version == "PySide2":
    from PySide2.QtCore import QDir, Qt, Signal, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
    from PySide2.QtWidgets import (
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMenu,
        QMessageBox,
        QPushButton,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
        QDialogButtonBox,
        QTableView,
        QAction,
        QFontDialog
    )
    from PySide2.QtGui import (
        QFontDatabase,
        QColor,
        QKeyEvent,
        QFocusEvent,
        QIntValidator
    )
elif ui_version == "PySide6":
    from PySide6.QtCore import QDir, Qt, Signal, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMenu,
        QMessageBox,
        QPushButton,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
        QDialogButtonBox,
        QTableView,
        QAction,
        QFontDialog
    )
    from PySide6.QtGui import (
        QFontDatabase,
        QColor,
        QKeyEvent,
        QFocusEvent,
        QIntValidator
    )
else:
    from PyQt5.QtCore import QDir, Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
    from PyQt5.QtCore import pyqtSignal as Signal
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMenu,
        QMessageBox,
        QPushButton,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
        QDialogButtonBox,
        QTableView,
        QAction,
        QFontDialog
    )
    from PyQt5.QtGui import (
        QFontDatabase,
        QColor,
        QKeyEvent,
        QFocusEvent,
        QIntValidator
    )
