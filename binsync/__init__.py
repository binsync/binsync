__version__ = "2.10.1"

#
# logging
#

import logging
logging.getLogger("binsync").addHandler(logging.NullHandler())
from binsync.loggercfg import Loggers
loggers = Loggers()
del Loggers
del logging

import binsync.data
import binsync.common


