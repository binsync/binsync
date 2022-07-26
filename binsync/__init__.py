VERSION = "2.5.0"

import logging

logging.getLogger("binsync").addHandler(logging.NullHandler())
from binsync.loggercfg import Loggers

loggers = Loggers()
del Loggers
del logging

from binsync.data import *
from binsync import common
from binsync.core.client import Client, ConnectionWarnings
