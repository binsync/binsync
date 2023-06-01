__version__ = "3.10.14"

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
import binsync.api
