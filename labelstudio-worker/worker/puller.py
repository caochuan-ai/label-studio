import logging
import os
import threading
import time

from .client import LabelStudio
from .runner import safe_error

logger = logging.getLogger(__name__)
STATUS = {'queued': 'copying', 'running': 'copying', 'completed': 'success', 'partial': 'fail', 'failed': 'fail'}
REPORT_FIELDS = ('id', 'attempt', 'phase', 'total', 'completed', 'failed', 'current_task', 'file_progress', 'error', 'errors')


class Puller:
    interval = 10
    timeout = 30

    def __init__(self, store, runner):
        self.store, self.runner = store, runner
        self.stop = threading.Event()
        self.thread = None
        self.current_id = None
        self.last_heartbeat = None

    def start(self):
        self.thread = threading.Thread(target=self.loop, name='copy-heartbeat', daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=10)

    def tick(self, client):
        report = None
        if self.current_id:
            job = self.store.get(self.current_id)
            report = {key: job[key] for key in REPORT_FIELDS}
            report['status'] = STATUS[job['status']]
        result = client.heartbeat(self.store.worker_id, report)
        self.last_heartbeat = time.monotonic()
        assignment = result['job']
        if assignment:
            job = self.store.accept_assignment(assignment)
            self.current_id = job['id']
            self.runner.authorized = (job['id'], job['attempt'])
        else:
            self.current_id = None
            self.runner.authorized = None

    def loop(self):
        client = LabelStudio(os.environ['LABEL_STUDIO_TOKEN'])
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                try:
                    self.tick(client)
                except Exception as exc:
                    logger.warning('Copy heartbeat failed: %s', safe_error(exc))
                self.stop.wait(max(0, self.interval - (time.monotonic() - started)))
        finally:
            client.close()

    @property
    def ready(self):
        return self.last_heartbeat is not None and time.monotonic() - self.last_heartbeat <= self.timeout
