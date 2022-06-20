import threading
import logging
from queue import PriorityQueue
from time import sleep
import time
from threading import Thread

l = logging.getLogger(__name__)

class FailedJob:
    def __init__(self, reason):
        self.reason = reason


class Job:
    def __init__(self, function, *args, **kwargs):
        self.function = function
        self.args = args
        self.kwargs = kwargs

        self.ret_value = None
        self.finish_event = threading.Event()

    def execute(self):
        self.ret_value = self.function(*self.args, **self.kwargs)
        self.finish_event.set()


class Scheduler:
    def __init__(self, cache, sleep_interval=0.05):
        #Thread.__init__(self)
        self.sleep_interval = sleep_interval
        self._worker = Thread(target=self._worker_thread)
        self._job_queue = PriorityQueue()
        self._work = False
        self.cache = cache


    #def run(self) -> None:
    #    self._work = True
    #    while self._work:
    #        self._complete_a_job(block=True)

    def stop_worker_thread(self):
        self._work = False

    def start_worker_thread(self):
        self._work = True
        self._worker.setDaemon(True)
        self._worker.start()

    def _worker_thread(self):
        while self._work:
            self._complete_a_job(block=True)

    def schedule_job(self, job: Job, priority=3):
        if priority == 1:
            l.info(f"Scheduled job for priority {priority}")
        self._job_queue.put_nowait((priority, job,))

    def schedule_and_wait_job(self, job: Job, priority=3, timeout=30):
        self.schedule_job(job, priority=priority)
        try:
            job.finish_event.wait(timeout=timeout)
        except Exception as e:
            return FailedJob(e)
        else:
            return job.ret_value

    def _complete_a_job(self, block=False):
        if block:
            _, job = self._job_queue.get()
        elif self._job_queue.not_empty:
            _, job = self._job_queue.get_nowait()
        else:
            return

        job.execute()
