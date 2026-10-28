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
        self.last_log = 0.0
        self.connection_failed = False

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
        previous = self.runner.authorized
        result = client.heartbeat(self.store.worker_id, report)
        self.last_heartbeat = time.monotonic()
        if self.last_log == 0 or self.connection_failed or self.last_heartbeat - self.last_log >= 60:
            logger.info('event=heartbeat_ok worker=%s active_job=%s report_status=%s', self.store.worker_id,
                        self.current_id or '-', report['status'] if report else 'idle')
            self.last_log = self.last_heartbeat
        self.connection_failed = False
        assignment = result['job']
        if assignment:
            job = self.store.accept_assignment(assignment)
            self.current_id = job['id']
            self.runner.authorized = (job['id'], job['attempt'])
            if previous != self.runner.authorized:
                logger.info('event=job_claimed job=%s project=%s attempt=%s worker=%s', job['id'], job['project'], job['attempt'], self.store.worker_id)
        else:
            self.current_id = None
            self.runner.authorized = None
            if previous:
                logger.info('event=job_report_accepted job=%s status=%s', previous[0], report['status'] if report else '-')

    def loop(self):
        client = LabelStudio(os.environ['LABEL_STUDIO_TOKEN'])
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                try:
                    self.tick(client)
                except Exception as exc:
                    self.connection_failed = True
                    logger.warning('event=heartbeat_failed worker=%s error=%s', self.store.worker_id, safe_error(exc))
                self.stop.wait(max(0, self.interval - (time.monotonic() - started)))
        finally:
            client.close()

    @property
    def ready(self):
        return self.last_heartbeat is not None and time.monotonic() - self.last_heartbeat <= self.timeout
