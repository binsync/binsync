__version__ = "2.8.0"

#
# logging
#

import logging
logging.getLogger("binsync").addHandler(logging.NullHandler())
from binsync.loggercfg import Loggers
loggers = Loggers()
del Loggers
del logging

from binsync.data import *
from binsync import common
from binsync.common import BinSyncController, SyncControlStatus
from binsync.core.client import Client, ConnectionWarnings, BINSYNC_ROOT_BRANCH
