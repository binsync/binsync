import signal
import sys
from functools import wraps

class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type_, value, traceback):
        signal.alarm(0)


def timeout_after(func):
    @wraps(func)
    def _timeout_after(*args, **kwargs):
        seconds = kwargs.get('timeout', 60*5)
        try:
            with timeout(seconds=seconds):
                func(*args, **kwargs)
        except TimeoutError:
            sys.exit(1)

    return _timeout_after
