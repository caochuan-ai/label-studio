import random
import threading
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from worker.app import create_app
from worker.geometry import box, media_field, transform_results, video_sequence
from worker.media import crop_image, crop_video, probe
from worker.schemas import CopyRequest
from worker.store import Store


CROP = dict(x0=25, y0=20, x1=75, y1=80)


def test_image_clip_and_remove_related_results():
    results = [
        {'id': 'inside', 'type': 'rectanglelabels', 'original_width': 100, 'original_height': 100,
         'value': dict(x=10, y=30, width=40, height=20, rectanglelabels=['Car'])},
        {'id': 'outside', 'type': 'rectanglelabels', 'value': dict(x=0, y=0, width=10, height=10)},
        {'id': 'outside', 'type': 'labels', 'value': {'labels': ['Car']}},
        {'type': 'relation', 'from_id': 'inside', 'to_id': 'outside'},
    ]
    result = transform_results(results, 100, 100, CROP)
    assert len(result) == 1
    assert result[0]['value']['x'] == 0
    assert result[0]['value']['width'] == 50
    assert result[0]['original_width'] == 50
    assert results[0]['value']['x'] == 10


def interpolate(sequence, frame):
    left = max((p for p in sequence if p['frame'] <= frame), key=lambda p: p['frame'])
    if left['frame'] == frame:
        return left
    right = min((p for p in sequence if p['frame'] > frame), key=lambda p: p['frame'])
    fraction = (frame - left['frame']) / (right['frame'] - left['frame'])
    return dict(left, **{k: left[k] + fraction * (right[k] - left[k]) for k in ('x', 'y', 'width', 'height')})


def test_video_clipping_preserves_every_frame_not_only_endpoints():
    random.seed(42)
    for _ in range(100):
        source = [dict(frame=frame, time=frame / 25, enabled=True, rotation=0,
                       x=random.uniform(-30, 90), y=random.uniform(-30, 90),
                       width=random.uniform(2, 70), height=random.uniform(2, 70)) for frame in (1, 50, 100)]
        result = video_sequence(source, 100, 100, CROP)
        for frame in range(1, 101):
            expected = box(interpolate(source, frame), 100, 100, CROP)
            if not result:
                assert expected is None
                continue
            actual = interpolate(result, frame)
            assert actual['enabled'] == (expected is not None)
            if expected:
                for key in ('x', 'y', 'width', 'height'):
                    assert actual[key] == pytest.approx(expected[key], abs=1e-7)


def test_video_preserves_disabled_segments_and_compact_long_tracks():
    source = [dict(frame=1, x=30, y=30, width=10, height=10, enabled=False),
              dict(frame=1000000, x=40, y=30, width=10, height=10, enabled=True)]
    result = video_sequence(source, 100, 100, CROP)
    assert len(result) == 2
    assert not result[0]['enabled']


@pytest.mark.parametrize('result', [
    {'type': 'polygonlabels', 'value': {}},
    {'type': 'rectanglelabels', 'value': dict(x=1, y=1, width=10, height=10, rotation=30)},
])
def test_reject_unsupported_annotations(result):
    with pytest.raises(ValueError):
        transform_results([result], 100, 100, CROP)


def request_data():
    return dict(project_id=1, new_project_name='Cropped', crop=CROP,
                source_storage={'bucket': 'test', 'prefix': 'media', 'region_name': 'us-east-1'},
                idempotency_key=str(uuid4()))


def test_store_idempotence_recovery_and_isolated_history(tmp_path):
    store = Store(tmp_path)
    request = CopyRequest(**request_data()).model_dump(mode='json')
    job_id = request['idempotency_key']
    store.create(job_id, 7, request)
    store.create(job_id, 7, request)
    assert len(store.history(7, 1)) == 1
    assert not store.history(8, 1)
    assert 'private-token' not in str(store.get(job_id))
    with pytest.raises(ValueError):
        store.create(job_id, 7, dict(request, new_project_name='Different'))
    store.add_items(job_id, [1, 2])
    store.finish_item(job_id, 1, target=100)
    store.finish_item(job_id, 2, error='failed')
    store.update(job_id, status='running')
    restarted = Store(tmp_path)
    restarted.recover()
    assert restarted.get(job_id)['status'] == 'queued'
    assert restarted.get(job_id)['completed'] == 1
    restarted.update(job_id, status='partial')
    assert restarted.retry(job_id, 7)
    assert restarted.next_item(job_id) == 2


def test_concurrent_duplicate_submissions_and_single_runner_lock(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from worker.runner import Runner
    store = Store(tmp_path)
    request = CopyRequest(**request_data()).model_dump(mode='json')
    job_id = request['idempotency_key']
    with ThreadPoolExecutor(max_workers=4) as executor:
        jobs = list(executor.map(lambda _: store.create(job_id, 7, request), range(4)))
    assert {job['id'] for job in jobs} == {job_id}
    assert len(store.history(7, 1)) == 1
    store.update(job_id, status='completed')
    first, second = Runner(store), Runner(store)
    try:
        first.start()
        with pytest.raises(BlockingIOError):
            second.start()
    finally:
        first.close()
        second.close()


def test_health_and_worker_requires_own_user_token(tmp_path, monkeypatch):
    monkeypatch.setenv('LABEL_STUDIO_TOKEN', 'private-token')
    monkeypatch.setenv('LABEL_STUDIO_URL', 'http://labelstudio:8080')
    monkeypatch.setenv('WORKER_DATA_DIR', str(tmp_path))
    with TestClient(create_app(run_worker=False)) as client:
        health = client.get('/health')
        assert health.status_code == 200
        assert health.json()['heartbeat_interval'] == 10
        assert not health.json()['ready']
        assert client.post('/project_copy', json=request_data()).status_code == 404
        assert 'private-token' not in str(client.app.state.store.path.read_bytes())
    monkeypatch.delenv('LABEL_STUDIO_TOKEN')
    with pytest.raises(RuntimeError, match='LABEL_STUDIO_TOKEN'):
        with TestClient(create_app(run_worker=False)):
            pass


def test_puller_reports_progress_and_recovers_lost_assignment(tmp_path):
    from worker.runner import Runner
    from worker.puller import Puller
    from unittest.mock import Mock
    store = Store(tmp_path)
    runner = Runner(store, require_assignment=True)
    puller = Puller(store, runner)
    request = request_data()
    job_id = request['idempotency_key']
    assignment = {'id': job_id, 'owner': 7, 'attempt': 1, 'request': request}
    client = Mock()
    client.heartbeat.return_value = {'job': assignment}
    assert not puller.ready
    puller.tick(client)
    assert puller.ready
    assert runner.authorized == (job_id, 1)
    store.add_items(job_id, [1])
    store.finish_item(job_id, 1, target=5)
    store.update(job_id, status='completed')
    # A lost completion response is safe: report success again, never run the task again.
    client.heartbeat.side_effect = RuntimeError('offline')
    with pytest.raises(RuntimeError):
        puller.tick(client)
    client.heartbeat.side_effect = None
    client.heartbeat.return_value = {'job': None}
    puller.tick(client)
    assert client.heartbeat.call_args[0][1]['status'] == 'success'
    assert runner.authorized is None
    assert store.get(job_id)['completed'] == 1
    assert Store(tmp_path).worker_id == store.worker_id
    puller.last_heartbeat -= 31
    assert not puller.ready


def test_puller_retry_attempt_preserves_completed_tasks(tmp_path):
    store = Store(tmp_path)
    request = request_data()
    assignment = {'id': request['idempotency_key'], 'owner': 7, 'attempt': 1, 'request': request}
    job = store.accept_assignment(assignment)
    store.add_items(job['id'], [1, 2])
    store.finish_item(job['id'], 1, target=100)
    store.finish_item(job['id'], 2, error='bad')
    store.update(job['id'], status='partial')
    again = store.accept_assignment(dict(assignment, attempt=2))
    assert again['status'] == 'queued'
    assert again['attempt'] == 2
    assert again['completed'] == 1
    assert store.next_item(job['id']) == 2
    with pytest.raises(ValueError, match='Stale'):
        store.accept_assignment(assignment)


def test_actual_png_crop(tmp_path):
    source, target = tmp_path / 'source.png', tmp_path / 'target.png'
    image = Image.new('RGB', (100, 100))
    for x in range(100):
        for y in range(100):
            image.putpixel((x, y), (x, y, 0))
    image.save(source)
    info = crop_image(source, target, CROP)
    assert info == {'width': 100, 'height': 100}
    with Image.open(target) as output:
        assert output.size == (50, 60)
        assert output.getpixel((0, 0)) == (25, 20, 0)


def test_actual_h264_crop_preserves_frames_and_audio(tmp_path):
    import shutil
    import subprocess
    if not shutil.which('ffmpeg'):
        pytest.skip('FFmpeg is required for the media integration test')
    source, target = tmp_path / 'source.mp4', tmp_path / 'target.mp4'
    subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'testsrc2=size=160x120:rate=25:duration=1',
                    '-f', 'lavfi', '-i', 'sine=frequency=1000:duration=1', '-c:v', 'libx264', '-c:a', 'aac',
                    '-pix_fmt', 'yuv420p', '-threads', '1', str(source)], check=True)
    info = crop_video(source, target, dict(x0=21, y0=11, x1=121, y1=91), lambda p: None, threading.Event())
    result = probe(target, count=True)
    assert (result['width'], result['height'], result['frames']) == (100, 80, 25)
    assert info['frames'] == 25
    audio = subprocess.check_output(['ffprobe', '-v', 'error', '-select_streams', 'a', '-show_entries',
                                     'stream=codec_name', '-of', 'csv=p=0', str(target)])
    assert b'aac' in audio


def test_actual_h264_variable_frame_rate_keeps_frame_timestamps(tmp_path):
    import json
    import subprocess
    source, target = tmp_path / 'vfr.mp4', tmp_path / 'cropped.mp4'
    subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'testsrc2=size=160x120:rate=25:duration=1',
                    '-vf', 'setpts=if(lt(N\\,12)\\,N/(25*TB)\\,(12/25+(N-12)/12.5)/TB)',
                    '-fps_mode', 'vfr', '-c:v', 'libx264', '-threads', '1', str(source)], check=True)
    crop_video(source, target, dict(x0=20, y0=10, x1=120, y1=90), lambda p: None, threading.Event())

    def times(path):
        result = subprocess.check_output(['ffprobe', '-v', 'error', '-select_streams', 'v:0', '-show_entries',
                                          'frame=best_effort_timestamp_time', '-of', 'json', str(path)])
        return [float(frame['best_effort_timestamp_time']) for frame in json.loads(result)['frames']]

    assert times(source) == pytest.approx(times(target), abs=0.002)


def test_config_rejects_multiple_media():
    with pytest.raises(ValueError):
        media_field('<View><Video value="$a"/><Image value="$b"/></View>')


def test_pipeline_retry_after_lost_commit_response_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv('LABEL_STUDIO_TOKEN', 'test-token')
    from worker.runner import Runner
    store = Store(tmp_path / 'state')
    (store.directory / 'tmp').mkdir()
    request = CopyRequest(**request_data()).model_dump(mode='json')
    job_id = request['idempotency_key']
    store.create(job_id, 7, request)
    config = '<View><Image name="image" value="$image"/></View>'
    committed, uploaded = {}, []

    class FakeLabelStudio:
        def __init__(self, *args, **kwargs):
            pass

        def call(self, method, path, **kwargs):
            if path == 'source/':
                return {'label_config': config}
            if path.endswith('/tasks/'):
                return {'ids': [1, 2] if kwargs['params']['after'] == 0 else []}
            if path == f'sessions/{job_id}/':
                return {'target_project': 20}
            task_id = int(path.strip('/').split('/')[-1])
            if method == 'GET':
                return {'target_task': committed[task_id]} if task_id in committed else {
                    'data': {'image': 'source'}, 'media_url': 'https://example.com/image.png',
                    'label_config': config, 'revision': 'revision', 'annotations': [], 'predictions': [], 'drafts': []}
            committed[task_id] = task_id + 100
            if task_id == 1:
                raise RuntimeError('Label Studio bridge returned HTTP 502')
            return {'target_task': committed[task_id]}

        def close(self):
            pass

    class FakeS3:
        def head_bucket(self, **kwargs):
            pass

        def upload_file(self, path, bucket, key, **kwargs):
            with Image.open(path) as image:
                assert image.size == (50, 60)
            uploaded.append(key)
            assert kwargs['Config'].use_threads is False

    monkeypatch.setattr('worker.runner.LabelStudio', FakeLabelStudio)
    monkeypatch.setattr('worker.runner.boto3.client', lambda *args, **kwargs: FakeS3())
    monkeypatch.setattr('worker.runner.download', lambda url, path, *args: Image.new('RGB', (100, 100)).save(path, 'PNG'))
    runner = Runner(store)
    runner.run(store.next_job())
    assert store.get(job_id)['status'] == 'partial'
    assert store.get(job_id)['completed'] == 1
    assert len(uploaded) == 2
    store.retry(job_id, 7)
    runner.run(store.next_job())
    assert store.get(job_id)['status'] == 'completed'
    assert store.get(job_id)['completed'] == 2
    assert len(uploaded) == 2


def test_heartbeat_continues_during_serial_copy_and_no_job_runs_before_claim(tmp_path):
    from worker.runner import Runner
    from worker.puller import Puller
    from unittest.mock import Mock
    store = Store(tmp_path)
    request = request_data()
    assignment = {'id': request['idempotency_key'], 'owner': 7, 'attempt': 1, 'request': request}
    store.accept_assignment(assignment)
    runner = Runner(store, require_assignment=True)
    entered, release = threading.Event(), threading.Event()

    def slow_copy(job):
        store.update(job['id'], status='running')
        entered.set()
        release.wait(3)
        store.update(job['id'], status='completed')

    runner.run = slow_copy
    try:
        runner.start()
        assert not entered.wait(0.05)
        client = Mock()
        client.heartbeat.return_value = {'job': assignment}
        puller = Puller(store, runner)
        puller.tick(client)
        assert entered.wait(2)
        puller.tick(client)
        assert client.heartbeat.call_count == 2
        assert client.heartbeat.call_args[0][1]['status'] == 'copying'
        assert not release.is_set()
    finally:
        release.set()
        runner.close()
