import logging.config
import tempfile
from datetime import datetime

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
_, tempfilename = tempfile.mkstemp(prefix=timestamp + '.binsync.', suffix='.log')

default_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "console": {
            "format": "%(levelname)-7s | %(asctime)s | %(name)-8s | %(message)s"
        },
        "logfile": {
            "format": "%(levelname)-7s | %(asctime)s | %(name)-8s | %(message)s"
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "console",
            "stream": "ext://sys.stdout"
        },

        "local_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "logfile",
            "filename": tempfilename,
            "maxBytes": 1000000,
            "backupCount": 20,
            "encoding": "utf8",
            "delay": True
        }
    },

    "root": {
        "level": "DEBUG",
        "handlers": ["console", "local_file_handler"],
    }
}


class Loggers:
    """
    Logger Manager.
    """
    IN_SCOPE_LOGGERS = ('binsync', 'ida_binsync', 'angr_binsync', 'binja_binsync')

    def __init__(self):
        self._loggers = {}
        self.load_all_loggers()
        self.profiling_enabled = False

        # disable filelock info logs
        logging.getLogger("filelock").setLevel(logging.WARNING)

        self.config_dict = None
        if default_config is not None:
            self.config_dict = default_config
        if self.config_dict is not None:
            logging.config.dictConfig(self.config_dict)
        self.handler = logging.StreamHandler()
        self.handler.setFormatter(logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))

    def load_all_loggers(self):
        for name, logger in logging.Logger.manager.loggerDict.items():
            if any(name.startswith(x + '.') or name == x for x in self.IN_SCOPE_LOGGERS):
                self._loggers[name] = logger

    def __getattr__(self, k):
        real_k = k.replace('_', '.')
        if real_k in self._loggers:
            return self._loggers[real_k]
        else:
            raise AttributeError(k)

    def __dir__(self):
        return list(super(Loggers, self).__dir__()) + list(self._loggers.keys())


def is_enabled_for(logger, level):
    if level == 1:
        from .. import loggers
        return loggers.profiling_enabled
    return originalIsEnabledFor(logger, level)


originalIsEnabledFor = logging.Logger.isEnabledFor

# Override isEnabledFor() for Logger class
logging.Logger.isEnabledFor = is_enabled_for
