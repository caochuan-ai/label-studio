import copy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone
from rest_framework.authtoken.models import Token
from io_storages.s3.models import S3ImportStorage, S3ImportStorageLink
from organizations.models import Organization
from projects.copy_api import snapshot
from projects.models import Project, ProjectCopySession, ProjectCopyJob, ProjectCopyWorker
from rest_framework.test import APIClient
from tasks.models import Annotation, AnnotationDraft, Prediction, Task
from users.models import User


CONFIG = '<View><Image name="image" value="$image"/><RectangleLabels name="box" toName="image"><Label value="Car"/></RectangleLabels></View>'


class ProjectCopyBridgeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='copy-test@example.com', password='test-password')
        self.org = Organization.create_organization(created_by=self.user)
        self.user.active_organization = self.org
        self.user.save()
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.project = Project.objects.create(title='Original', organization=self.org, created_by=self.user, label_config=CONFIG)
        self.task = Task.objects.create(project=self.project, data={'image': 'https://example.com/image.png'}, meta={'test': 1})
        self.result = [{'id': 'box1', 'from_name': 'box', 'to_name': 'image', 'type': 'rectanglelabels',
                        'original_width': 100, 'original_height': 100,
                        'value': {'x': 20, 'y': 20, 'width': 40, 'height': 40, 'rectanglelabels': ['Car']}}]
        self.prediction = Prediction.objects.create(task=self.task, project=self.project, result=self.result, score=0.9, model_version='v1')
        self.annotation = Annotation.objects.create(task=self.task, project=self.project, result=self.result,
            completed_by=self.user, parent_prediction=self.prediction, ground_truth=True)
        AnnotationDraft.objects.create(task=self.task, annotation=self.annotation, user=self.user, result=self.result)
        self.job = str(uuid4())
        self.worker_id = str(uuid4())
        self.heartbeat = '/api/projects/copy/heartbeat/'
        self.base = f'/api/projects/{self.project.id}/copy/'
        self.session_url = self.base + f'sessions/{self.job}/'
        self.task_url = self.session_url + f'tasks/{self.task.id}/'
        self.config = {'new_project_name': 'Copied', 'crop': {'x0': 10, 'y0': 10, 'x1': 90, 'y1': 90},
                       'label_config': CONFIG, 'source_storage': {'bucket': 'destination', 'prefix': 'copy-' + self.job, 'aws_access_key_id': 'fixture-ak', 'aws_secret_access_key': 'fixture-secret'}}

    def enqueue(self, config=None):
        body = config or dict(self.config, source_storage=dict(self.config['source_storage'], prefix=''))
        body = {key: value for key, value in body.items() if key != 'label_config'}
        response = self.client.post(self.base + 'jobs/', dict(body, idempotency_key=self.job), format='json')
        self.assertEqual(response.status_code, 202, response.content)
        return response.json()

    def claim(self, worker_id=None, report=None):
        worker_id = worker_id or self.worker_id
        response = self.client.post(self.heartbeat, {'worker_id': worker_id, 'report': report}, format='json')
        self.assertEqual(response.status_code, 200, response.content)
        self.client.credentials(HTTP_X_COPY_WORKER=worker_id, HTTP_X_COPY_ATTEMPT='1')
        return response.json()

    def initialize(self):
        self.enqueue()
        self.claim()
        response = self.client.post(self.session_url, self.config, format='json')
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['target_project']

    def payload(self):
        self.task.refresh_from_db()
        data = snapshot(self.task)
        key = self.config['source_storage']['prefix'] + f'/{self.task.id}.png'
        data['data']['image'] = f's3://destination/{key}'
        for group in ('annotations', 'predictions', 'drafts'):
            for item in data[group]:
                item['result'] = copy.deepcopy(self.result)
                item['result'][0]['value']['x'] = 12.5
                item['result'][0]['original_width'] = 80
        return {key_: data[key_] for key_ in ('data', 'revision', 'annotations', 'predictions', 'drafts')} | {'key': key}

    def test_idempotent_project_and_atomic_task_copy(self):
        target_id = self.initialize()
        self.assertEqual(self.initialize(), target_id)
        self.assertEqual(ProjectCopySession.objects.count(), 1)
        payload = self.payload()
        response = self.client.post(self.task_url, payload, format='json')
        self.assertEqual(response.status_code, 201, response.content)
        new_id = response.json()['target_task']
        again = self.client.post(self.task_url, payload, format='json')
        self.assertEqual(again.status_code, 200, again.content)
        self.assertEqual(again.json()['target_task'], new_id)
        target = Task.objects.get(pk=new_id)
        self.assertEqual(target.project_id, target_id)
        self.assertEqual(target.annotations.count(), 1)
        self.assertEqual(target.predictions.count(), 1)
        self.assertEqual(target.drafts.count(), 1)
        copied = target.annotations.get()
        self.assertEqual(copied.completed_by_id, self.user.pk)
        self.assertEqual(copied.created_at, self.annotation.created_at)
        self.assertEqual(copied.parent_prediction_id, target.predictions.get().id)
        self.assertEqual(target.drafts.get().annotation_id, copied.id)
        self.assertEqual(target.total_annotations, 1)
        self.assertEqual(target.total_predictions, 1)
        self.assertEqual(target.project.summary.all_data_columns['image'], 1)
        self.assertEqual(S3ImportStorageLink.objects.filter(task=target).count(), 1)
        self.annotation.refresh_from_db()
        self.assertEqual(self.annotation.result, self.result)

    def test_changed_source_rejected_without_partial_task(self):
        target_id = self.initialize()
        payload = self.payload()
        self.task.data['extra'] = 'changed'
        self.task.save()
        response = self.client.post(self.task_url, payload, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Task.objects.filter(project_id=target_id).count(), 0)

    def test_cross_organization_access_denied(self):
        self.initialize()
        other = User.objects.create_user(email='other-copy@example.com', password='password')
        other.active_organization = Organization.create_organization(created_by=other)
        other.save()
        self.client.force_authenticate(other)
        self.assertEqual(self.client.get(self.base + 'source/').status_code, 404)
        self.assertEqual(self.client.get(self.task_url).status_code, 404)

    def test_queue_heartbeat_timeout_and_owner_isolation(self):
        waiting = self.enqueue()
        self.assertEqual(waiting['status'], 'waiting')
        self.assertEqual(self.enqueue()['id'], waiting['id'])
        before = self.client.get(self.base + 'jobs/').json()
        self.assertFalse(before['worker']['ready'])
        assignment = self.claim()['job']
        self.assertEqual(assignment['id'], self.job)
        self.assertNotIn('label_studio_token', assignment['request'])
        self.assertTrue(self.client.get(self.base + 'jobs/').json()['worker']['ready'])
        other_worker = str(uuid4())
        self.assertIsNone(self.claim(other_worker)['job'])
        now = timezone.now()
        ProjectCopyWorker.objects.update(last_seen=now - timedelta(seconds=31))
        self.assertFalse(self.client.get(self.base + 'jobs/').json()['worker']['ready'])
        # An offline job remains with its worker; reconnect recovers the same assignment.
        self.assertEqual(self.claim()['job']['id'], self.job)
        self.assertEqual(ProjectCopyJob.objects.get(pk=self.job).status, 'copying')
        other = User.objects.create_user(email='same-org@example.com', password='password')
        other.active_organization = self.org
        other.save()
        self.client.force_authenticate(other)
        self.assertEqual(self.client.post(self.heartbeat, {'worker_id': self.worker_id}, format='json').status_code, 403)
        self.assertIsNone(self.claim(str(uuid4()))['job'])

    def test_heartbeat_uses_real_label_studio_token(self):
        api = APIClient()
        self.assertEqual(api.post(self.heartbeat, {'worker_id': self.worker_id}, format='json').status_code, 401)
        api.credentials(HTTP_AUTHORIZATION='Token invalid')
        self.assertEqual(api.post(self.heartbeat, {'worker_id': self.worker_id}, format='json').status_code, 401)
        token, _ = Token.objects.get_or_create(user=self.user)
        api.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        self.assertEqual(api.post(self.heartbeat, {'worker_id': self.worker_id}, format='json').status_code, 200)

    def test_progress_failure_retry_fencing_and_secret_redaction(self):
        config = dict(self.config, source_storage={'bucket': 'destination', 'prefix': '',
                       'aws_access_key_id': 'private-access', 'aws_secret_access_key': 'private-secret'})
        self.enqueue(config)
        self.claim()
        report = {'id': self.job, 'attempt': 1, 'status': 'fail', 'phase': 'finished',
                  'total': 2, 'completed': 1, 'failed': 1, 'errors': [{'source': self.task.pk, 'error': 'failed'}]}
        self.claim(report=report)
        history = self.client.get(self.base + 'jobs/').json()
        self.assertEqual(history['jobs'][0]['status'], 'fail')
        self.assertNotIn('private-secret', str(history))
        for _ in range(3):
            self.assertIsNone(self.claim(report=report)['job'])
        failed_job = ProjectCopyJob.objects.get(pk=self.job)
        self.assertEqual(failed_job.status, 'fail')
        self.assertEqual(failed_job.attempt, 1)
        retry = self.client.post(self.base + f'jobs/{self.job}/', {}, format='json')
        self.assertEqual(retry.json()['status'], 'waiting')
        assignment = self.claim()['job']
        self.assertEqual(assignment['attempt'], 2)
        self.claim(report=report)  # A late report from attempt 1 cannot fail attempt 2.
        self.assertEqual(ProjectCopyJob.objects.get(pk=self.job).status, 'copying')
        self.assertEqual(self.client.post(self.session_url, self.config, format='json').status_code, 403)
        report.update(attempt=2, status='success', completed=2, failed=0, errors=[])
        self.claim(report=report)
        self.assertEqual(self.client.get(self.base + f'jobs/{self.job}/').json()['status'], 'success')

    def test_worker_pipeline_with_real_bridge_and_cropped_image(self):
        import sys
        import tempfile
        from pathlib import Path
        from PIL import Image

        sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'labelstudio-worker'))
        from worker.runner import Runner
        from worker.store import Store

        api = self.client
        base = self.base

        class BridgeClient:
            def __init__(self, *args, **kwargs):
                pass

            def call(self, method, path, **kwargs):
                response = api.get(base + path, kwargs.get('params', {})) if method == 'GET' else \
                    api.post(base + path, kwargs.get('json', {}), format='json')
                if response.status_code >= 400:
                    raise AssertionError(response.content)
                return response.json()

            def heartbeat(self, worker_id, report=None):
                response = api.post('/api/projects/copy/heartbeat/', {'worker_id': worker_id, 'report': report}, format='json')
                if response.status_code >= 400:
                    raise AssertionError(response.content)
                return response.json()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as temporary:
            store = Store(temporary)
            (store.directory / 'tmp').mkdir()
            storage = dict(self.config['source_storage'], region_name='us-east-1')
            request = dict(project_id=self.project.pk, new_project_name='Pipeline copy',
                           crop=self.config['crop'], source_storage=storage)
            self.enqueue(request)
            assignment = self.claim(store.worker_id)['job']
            store.create(self.job, self.user.pk, dict(assignment['request'], attempt=assignment['attempt']))
            uploads = []

            def upload(path, bucket, key, **kwargs):
                with Image.open(path) as image:
                    self.assertEqual(image.size, (80, 80))
                uploads.append(key)

            with patch.dict('os.environ', {'LABEL_STUDIO_TOKEN': 'test'}), patch('worker.runner.LabelStudio', BridgeClient), patch('worker.runner.boto3.client') as s3, \
                 patch('worker.runner.download', side_effect=lambda url, path, *args: Image.new('RGB', (100, 100)).save(path, 'PNG')):
                s3.return_value.upload_file.side_effect = upload
                Runner(store).run(store.next_job())
            job = store.get(self.job)
            self.assertEqual(job['status'], 'completed', job)
            self.assertEqual(job['completed'], 1)
            target = Task.objects.get(project_id=job['target_project'])
            self.assertEqual(target.annotations.get().result[0]['value']['x'], 12.5)
            self.assertEqual(target.predictions.get().result[0]['value']['width'], 50)
            self.assertEqual(target.drafts.get().result[0]['original_width'], 80)
            self.assertEqual(target.data['image'], 's3://destination/' + uploads[0])
            from worker.puller import Puller
            puller = Puller(store, Runner(store))
            puller.current_id = self.job
            puller.tick(BridgeClient())
            self.assertEqual(self.client.get(self.base + f'jobs/{self.job}/').json()['status'], 'success')

    def test_defaults_first_storage_credentials_and_change_validation(self):
        original = S3ImportStorage.objects.create(project=self.project, title='First S3', bucket='source', prefix='media',
            aws_access_key_id='original-ak', aws_secret_access_key='original-secret', aws_session_token='temporary-token')
        S3ImportStorage.objects.create(project=self.project, title='Second S3', bucket='second')
        response = self.client.get(self.base + 'defaults/')
        self.assertEqual(response.status_code, 200, response.content)
        defaults = response.json()
        self.assertEqual(defaults['storage_id'], original.pk)
        self.assertEqual(defaults['source_storage']['aws_secret_access_key'], 'original-secret')
        self.assertEqual(defaults['source_storage']['aws_session_token'], 'temporary-token')
        self.assertIn('no-store', response['Cache-Control'])
        body = dict(self.config, source_storage=defaults['source_storage'], idempotency_key=self.job)
        for prefix in ['media', ' /media/ ']:
            body['source_storage']['prefix'] = prefix
            result = self.client.post(self.base + 'jobs/', body, format='json')
            self.assertEqual(result.status_code, 400, result.content)
        body['source_storage']['prefix'] = 'cropped'
        result = self.client.post(self.base + 'jobs/', body, format='json')
        self.assertEqual(result.status_code, 202, result.content)
        self.assertNotIn('original-secret', result.content.decode())
        self.assertNotIn('original-ak', result.content.decode())
        self.assertNotIn('temporary-token', self.client.get(self.base + 'jobs/').content.decode())
        self.assertEqual(self.claim()['job']['request']['source_storage']['aws_secret_access_key'], 'original-secret')

    def test_missing_credentials_rejected_and_defaults_require_project_access(self):
        body = dict(self.config, source_storage={'bucket': 'destination'}, idempotency_key=self.job)
        response = self.client.post(self.base + 'jobs/', body, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ProjectCopyJob.objects.exists())
        outsider = User.objects.create_user(email='outsider@example.com')
        outsider.active_organization = Organization.create_organization(created_by=outsider)
        outsider.save()
        self.client.force_authenticate(outsider)
        self.assertIn(self.client.get(self.base + 'defaults/').status_code, [403, 404])

    def test_history_reverse_order_operator_and_read_only_other_users(self):
        self.enqueue()
        older = ProjectCopyJob.objects.get(pk=self.job)
        ProjectCopyJob.objects.filter(pk=older.pk).update(created_at=timezone.now() - timedelta(hours=1))
        colleague = User.objects.create_user(email='colleague@example.com', first_name='Copy Operator')
        colleague.active_organization = self.org
        colleague.save()
        self.org.add_user(colleague)
        newer = ProjectCopyJob.objects.create(id=uuid4(), source_project=self.project, created_by=colleague,
            configuration=older.configuration, status='fail')
        result = self.client.get(self.base + 'jobs/').json()['jobs']
        self.assertEqual([job['id'] for job in result], [str(newer.pk), str(older.pk)])
        self.assertEqual(result[0]['operator']['name'], 'Copy Operator')
        self.assertFalse(result[0]['can_retry'])
        self.assertTrue(result[1]['can_retry'])
        self.assertEqual(self.client.get(self.base + f'jobs/{newer.pk}/').status_code, 200)
        self.assertEqual(self.client.post(self.base + f'jobs/{newer.pk}/', {}, format='json').status_code, 404)
        self.assertNotIn('fixture-secret', str(result))
