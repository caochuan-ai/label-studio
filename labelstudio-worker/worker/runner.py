import fcntl
import os
import logging
import shutil
import tempfile
import threading
import time
from pathlib import Path

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from .logging_utils import error_location
from .client import LabelStudio
from .geometry import media_field, transform_task
from .media import Interrupted, crop_image, crop_video, download


logger = logging.getLogger(__name__)


def safe_error(exc):
    # Known validation errors contain only our own messages. SDK/HTTP errors can contain credentials/URLs.
    if isinstance(exc, NoCredentialsError):
        return ('NoCredentialsError: worker has no S3 credentials. Supply destination storage access key and secret key '
                'in a new copy request. '
                'LABEL_STUDIO_TOKEN only authenticates Label Studio API requests.')
    if isinstance(exc, PartialCredentialsError):
        return ('PartialCredentialsError: provide both AWS access key and secret key, '
                'and a session token when using temporary credentials.')
    if isinstance(exc, ClientError):
        # Service code and HTTP status are useful without exposing the SDK's request URL or message.
        code = str(exc.response.get('Error', {}).get('Code', 'Unknown'))
        code = ''.join(char for char in code if char.isalnum() or char in '_-')[:80]
        status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode', 'unknown')
        return f'S3 ClientError: code={code} http_status={status}; verify storage permissions and configuration'
    if isinstance(exc, ValueError):
        return str(exc)[:400]
    if isinstance(exc, RuntimeError) and str(exc).startswith(('Label Studio bridge', 'Media download')):
        return str(exc)
    return type(exc).__name__ + ': operation failed; verify connectivity, credentials and service configuration'


class AssignmentStop:
    def __init__(self, stop, valid):
        self.stop, self.valid = stop, valid

    def is_set(self):
        return self.stop.is_set() or not self.valid()

    def wait(self, seconds):
        until = time.monotonic() + seconds
        while not self.is_set() and time.monotonic() < until:
            self.stop.wait(min(0.1, max(0, until - time.monotonic())))
        return self.is_set()


class Runner:
    def __init__(self, store, require_assignment=False):
        self.store = store
        self.stop = threading.Event()
        self.lock = None
        self.thread = None
        self.require_assignment = require_assignment
        self.authorized = None
        self.job_stop = self.stop

    def start(self):
        self.lock = (self.store.directory / 'runner.lock').open('w')
        # Fail a second process instead of accidentally running multiple encoders.
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.store.recover()
        temp = self.store.directory / 'tmp'
        shutil.rmtree(temp, ignore_errors=True)
        temp.mkdir(mode=0o700)
        self.thread = threading.Thread(target=self.loop, name='project-copy', daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=65)
        if self.lock and (not self.thread or not self.thread.is_alive()):
            self.lock.close()

    def loop(self):
        while not self.stop.is_set():
            if self.require_assignment:
                assigned = self.authorized
                job = self.store.get(assigned[0], private=True) if assigned else None
                if job and (job['status'] != 'queued' or job['attempt'] != assigned[1]):
                    job = None
            else:
                job = self.store.next_job()
            if not job:
                self.stop.wait(1)
                continue
            try:
                self.run(job)
            except Interrupted:
                logger.warning('event=job_interrupted job=%s attempt=%s', job['id'], job['attempt'])
                self.store.update(job['id'], status='queued', phase='interrupted')
                if self.stop.is_set():
                    return
            except Exception as exc:
                logger.error('event=job_failed job=%s attempt=%s phase=%s error=%s trace=%s',
                             job['id'], job['attempt'], self.store.get(job['id'])['phase'], safe_error(exc), error_location(exc))
                self.store.update(job['id'], status='failed', phase='failed', error=safe_error(exc))

    def run(self, job):
        job_id, request = job['id'], job['request']
        started = time.monotonic()
        logger.info('event=job_start job=%s project=%s attempt=%s', job_id, request['project_id'], job['attempt'])
        assignment = (job_id, job['attempt'])
        self.job_stop = AssignmentStop(self.stop, lambda: self.authorized == assignment) if self.require_assignment else self.stop
        client = LabelStudio(os.environ['LABEL_STUDIO_TOKEN'], request['project_id'],
                             worker_id=self.store.worker_id, attempt=job['attempt'])
        try:
            self.store.update(job_id, status='running', phase='preparing', error=None)
            source = client.call('GET', 'source/')
            field = media_field(source['label_config'])
            storage = dict(request['source_storage'])
            if not storage.get('aws_access_key_id') or not storage.get('aws_secret_access_key'):
                raise ValueError('新 Source Storage 缺少 AK/SK，请在复制配置中补齐凭证后重新提交。')
            storage['prefix'] = '/'.join(filter(None, [storage['prefix'].strip('/'), 'copy-' + job_id]))
            s3 = boto3.client('s3', region_name=storage.get('region_name') or None,
                              endpoint_url=storage.get('s3_endpoint') or None,
                              aws_access_key_id=storage.get('aws_access_key_id') or None,
                              aws_secret_access_key=storage.get('aws_secret_access_key') or None,
                              aws_session_token=storage.get('aws_session_token') or None,
                              config=Config(connect_timeout=10, read_timeout=60, retries={'max_attempts': 3}))
            logger.info('event=storage_check job=%s', job_id)
            s3.head_bucket(Bucket=storage['bucket'])
            logger.info('event=storage_ready job=%s', job_id)
            session = client.call('POST', f'sessions/{job_id}/', json={
                'new_project_name': request['new_project_name'], 'source_storage': storage,
                'crop': request['crop'], 'label_config': source['label_config']})
            self.store.update(job_id, target_project=session['target_project'])
            logger.info('event=project_ready job=%s target_project=%s', job_id, session['target_project'])
            if not job['planned']:
                after = 0
                while True:
                    if self.job_stop.is_set():
                        raise Interrupted()
                    page = client.call('GET', f'sessions/{job_id}/tasks/', params={'after': after})
                    self.store.add_items(job_id, page['ids'])
                    if not page['ids']:
                        break
                    after = page['ids'][-1]
                self.store.update(job_id, planned=1)
            logger.info('event=tasks_planned job=%s total=%s', job_id, self.store.get(job_id)['total'])
            while not self.job_stop.is_set():
                task_id = self.store.next_item(job_id)
                if task_id is None:
                    break
                self.store.update(job_id, current_task=task_id, file_progress=0)
                try:
                    self.store.begin_item(job_id, task_id)
                    self.copy_task(client, s3, storage, field, request['crop'], job_id, task_id)
                except Interrupted:
                    raise
                except Exception as exc:
                    logger.error('event=task_failed job=%s task=%s phase=%s error=%s trace=%s', job_id, task_id,
                                 self.store.get(job_id)['phase'], safe_error(exc), error_location(exc))
                    self.store.finish_item(job_id, task_id, error=safe_error(exc))
            if self.job_stop.is_set():
                raise Interrupted()
            job = self.store.get(job_id)
            self.store.update(job_id, status='partial' if job['failed'] else 'completed', phase='finished',
                              current_task=None, file_progress=1)
            logger.info('event=job_finished job=%s status=%s completed=%s failed=%s elapsed=%.2fs',
                        job_id, 'fail' if job['failed'] else 'success', job['completed'], job['failed'], time.monotonic() - started)
        finally:
            client.close()

    def copy_task(self, client, s3, storage, field, crop, job_id, task_id):
        task_started = time.monotonic()
        logger.info('event=task_start job=%s task=%s media=%s', job_id, task_id, field['kind'])
        self.store.update(job_id, phase='loading_task', file_progress=0)
        path = f'sessions/{job_id}/tasks/{task_id}/'
        task = client.call('GET', path)
        if task.get('target_task'):
            logger.info('event=task_already_saved job=%s task=%s target_task=%s', job_id, task_id, task['target_task'])
            self.store.finish_item(job_id, task_id, target=task['target_task'])
            return
        if task['label_config'] != client.call('GET', 'source/')['label_config']:
            raise ValueError('Project labeling configuration changed during copy')
        last_update = [0.0]
        stage = {'name': None, 'started': time.monotonic(), 'logged': 0.0, 'percent': 0}

        def report(phase, fraction=0):
            now = time.monotonic()
            percent = int(fraction * 100)
            if phase != stage['name']:
                if stage['name']:
                    logger.info('event=stage_finished job=%s task=%s phase=%s elapsed=%.2fs', job_id, task_id, stage['name'], now - stage['started'])
                logger.info('event=stage_start job=%s task=%s phase=%s', job_id, task_id, phase)
                stage.update(name=phase, started=now, logged=now, percent=percent)
            elif now - stage['logged'] >= 10 or (percent >= 100 and stage['percent'] < 100):
                logger.info('event=stage_progress job=%s task=%s phase=%s progress=%s%% elapsed=%.2fs', job_id, task_id, phase, percent, now - stage['started'])
                stage.update(logged=now, percent=percent)
            if fraction in (0, 1) or now - last_update[0] > 1:
                self.store.update(job_id, phase=phase, file_progress=fraction)
                last_update[0] = now

        with tempfile.TemporaryDirectory(dir=self.store.directory / 'tmp') as directory:
            source = Path(directory) / 'input'
            video = field['kind'] == 'video'
            output = Path(directory) / ('output.mp4' if video else 'output.png')
            report('downloading')
            download(task['media_url'], source, client, lambda p: report('downloading', p), self.job_stop)
            report('cropping')
            info = crop_video(source, output, crop, lambda p: report('cropping', p), self.job_stop) if video else crop_image(source, output, crop)
            report('transforming')
            transformed = transform_task(task, info['width'], info['height'], crop)
            key = storage['prefix'] + '/' + str(task_id) + output.suffix
            transformed['data'][field['key']] = f"s3://{storage['bucket']}/{key}"
            report('uploading')
            extra = {'ContentType': 'video/mp4' if video else 'image/png'}
            if storage.get('aws_sse_kms_key_id'):
                extra.update(ServerSideEncryption='aws:kms', SSEKMSKeyId=storage['aws_sse_kms_key_id'])
            uploaded = [0]

            def upload_progress(size):
                if self.job_stop.is_set():
                    raise Interrupted()
                uploaded[0] += size
                report('uploading', min(uploaded[0] / output.stat().st_size, 1))

            s3.upload_file(str(output), storage['bucket'], key, ExtraArgs=extra, Callback=upload_progress,
                           Config=TransferConfig(use_threads=False, max_concurrency=1))
            report('saving')
            result = client.call('POST', path, json={
                'revision': task['revision'], 'data': transformed['data'], 'key': key,
                **{name: transformed[name] for name in ('annotations', 'predictions', 'drafts')}})
            self.store.finish_item(job_id, task_id, target=result['target_task'])
            logger.info('event=stage_finished job=%s task=%s phase=saving elapsed=%.2fs', job_id, task_id, time.monotonic() - stage['started'])
            logger.info('event=task_finished job=%s task=%s target_task=%s output_bytes=%s elapsed=%.2fs',
                        job_id, task_id, result['target_task'], output.stat().st_size, time.monotonic() - task_started)
