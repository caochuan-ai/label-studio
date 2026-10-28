"""Authenticated bridge between Label Studio and the standalone media copy service."""
import copy
import hashlib
import json
from urllib.parse import unquote, urlparse

from core.label_config import replace_task_data_undefined_with_config_field
from defusedxml import ElementTree
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import Max
from io_storages.functions import get_storage_by_url
from io_storages.s3.models import S3ImportStorage, S3ImportStorageLink
from projects.models import Project, ProjectCopySession, ProjectCopyTask
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from tasks.models import Annotation, Task


PROJECT_SETTINGS = (
    'description', 'label_config', 'expert_instruction', 'show_instruction', 'show_skip_button',
    'enable_empty_annotation', 'show_annotation_history', 'color', 'maximum_annotations', 'is_published',
    'model_version', 'is_draft', 'min_annotations_to_start_training', 'show_collab_predictions', 'sampling',
    'show_ground_truth_first', 'show_overlap_first', 'overlap_cohort_percentage', 'control_weights',
    'evaluate_predictions_automatically', 'skip_queue', 'reveal_preannotations_interactively',
)


def source_project(request, pk):
    project = get_object_or_404(Project.objects.for_user(request.user), pk=pk)
    return project


def get_session(request, pk, job_id, lock=False):
    source_project(request, pk)
    from projects.copy_queue import require_assignment
    require_assignment(request, pk, job_id, lock=lock)
    query = ProjectCopySession.objects.select_for_update() if lock else ProjectCopySession.objects
    session = get_object_or_404(query, id=job_id, source_project_id=pk, created_by=request.user)
    if not session.target_project_id:
        raise ValidationError('The destination project was deleted; create a new copy job')
    get_object_or_404(Project.objects.for_user(request.user), pk=session.target_project_id)
    return session


def media_key(config):
    media = [node for node in ElementTree.fromstring(config).iter() if node.tag in ('Image', 'Video')]
    if len(media) != 1 or not media[0].get('value', '').startswith('$'):
        raise ValidationError('Copy requires exactly one Image or Video field')
    key = media[0].get('value')[1:]
    if not key or '.' in key:
        raise ValidationError('Copy requires a top-level media field')
    return key


def record(instance):
    return {field.attname: copy.deepcopy(getattr(instance, field.attname)) for field in instance._meta.concrete_fields}


def snapshot(task):
    data = record(task)
    for name in ('annotations', 'predictions', 'drafts'):
        data[name] = [record(item) for item in getattr(task, name).order_by('id')]
    digest = hashlib.sha256(json.dumps(data, sort_keys=True, cls=DjangoJSONEncoder).encode()).hexdigest()
    replace_task_data_undefined_with_config_field(data['data'], task.project)
    data['revision'] = digest
    return data


def download_url(task, value):
    if not isinstance(value, str):
        raise ValidationError('Media field must contain a URL')
    parsed = urlparse(value)
    if parsed.scheme == 's3':
        storage = get_storage_by_url(value, task.project.get_all_storage_objects(type_='import'))
        if not isinstance(storage, S3ImportStorage):
            raise ValidationError('No source S3 storage found for this media')
        return storage.get_client().generate_presigned_url(
            'get_object', Params={'Bucket': parsed.netloc, 'Key': unquote(parsed.path.lstrip('/'))}, ExpiresIn=3600)
    if parsed.scheme in ('http', 'https') or (value.startswith('/') and not value.startswith('//')):
        if parsed.scheme in ('http', 'https') and task.project.task_data_login and task.project.task_data_password:
            return task.resolve_uri({'media': value}, task.project)['media']
        return value
    raise ValidationError('Only HTTP(S), local uploaded files and S3 media are supported')


class ProjectCopySourceAPI(APIView):
    def get(self, request, pk):
        project = source_project(request, pk)
        media_key(project.label_config)
        return Response({'user_id': request.user.pk, 'label_config': project.label_config, 'title': project.title})


class CopyStorageSerializer(serializers.Serializer):
    bucket = serializers.CharField(max_length=255)
    prefix = serializers.CharField(max_length=1024, required=False, allow_blank=True, default='')
    region_name = serializers.CharField(required=False, allow_blank=True, default='')
    s3_endpoint = serializers.URLField(required=False, allow_blank=True, default='')
    aws_access_key_id = serializers.CharField(required=False, allow_blank=True, default='')
    aws_secret_access_key = serializers.CharField(required=False, allow_blank=True, default='')
    aws_session_token = serializers.CharField(required=False, allow_blank=True, default='')
    aws_sse_kms_key_id = serializers.CharField(required=False, allow_blank=True, default='')

    def validate(self, data):
        if bool(data.get('aws_access_key_id')) != bool(data.get('aws_secret_access_key')):
            raise ValidationError('Access key and secret key must be supplied together')
        return data


class CopySessionSerializer(serializers.Serializer):
    new_project_name = serializers.CharField(max_length=200)
    crop = serializers.DictField(child=serializers.IntegerField(min_value=0))
    label_config = serializers.CharField()
    source_storage = CopyStorageSerializer()

    def validate_crop(self, crop):
        if set(crop) != {'x0', 'y0', 'x1', 'y1'} or crop['x1'] <= crop['x0'] or crop['y1'] <= crop['y0']:
            raise ValidationError('Invalid crop rectangle')
        return crop


class ProjectCopySessionAPI(APIView):
    @transaction.atomic
    def post(self, request, pk, job_id):
        source = source_project(request, pk)
        from projects.copy_queue import require_assignment
        job = require_assignment(request, pk, job_id, lock=True)
        # Serialize creation for the same source, including retries after a lost response.
        Project.objects.select_for_update().get(pk=source.pk)
        serializer = CopySessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        expected = copy.deepcopy(job.configuration)
        storage = expected['source_storage']
        storage['prefix'] = '/'.join(filter(None, [storage.get('prefix', '').strip('/'), 'copy-' + str(job.pk)]))
        if any(data[key] != expected[key] for key in ('new_project_name', 'crop', 'source_storage')):
            raise ValidationError('Worker configuration differs from the queued job')
        config = {key: data[key] for key in ('new_project_name', 'crop', 'label_config')}
        config.update(bucket=data['source_storage']['bucket'], prefix=data['source_storage']['prefix'])
        existing = ProjectCopySession.objects.filter(pk=job_id).first()
        if existing:
            session = get_session(request, pk, job_id)
            if session.configuration != config:
                raise ValidationError('Copy configuration changed for an existing job')
        else:
            if source.label_config != data['label_config']:
                raise ValidationError('Source labeling configuration changed')
            media_key(source.label_config)
            target = Project.objects.create(title=data['new_project_name'], organization=source.organization,
                                            created_by=request.user, **{key: copy.deepcopy(getattr(source, key)) for key in PROJECT_SETTINGS})
            # The worker validates access. Unlike ordinary source sync, an empty prefix is valid here.
            storage = S3ImportStorage.objects.create(project=target, use_blob_urls=True, presign=True,
                                                     title='Copied media', **data['source_storage'])
            session = ProjectCopySession.objects.create(id=job_id, source_project=source, target_project=target,
                created_by=request.user, storage_id=storage.id, configuration=config,
                source_max_task_id=source.tasks.aggregate(value=Max('id'))['value'] or 0)
        return Response({'target_project': session.target_project_id, 'storage_id': session.storage_id})


class ProjectCopyTasksAPI(APIView):
    def get(self, request, pk, job_id):
        session = get_session(request, pk, job_id)
        try:
            after = max(0, int(request.query_params.get('after', 0)))
        except ValueError:
            raise ValidationError('Invalid task cursor')
        ids = list(Task.objects.filter(project_id=pk, id__gt=after, id__lte=session.source_max_task_id)
                   .order_by('id').values_list('id', flat=True)[:200])
        return Response({'ids': ids})


def clone_record(source, excluded, **overrides):
    values = record(source)
    for key in set(excluded) | {'id', 'created_at', 'updated_at'}:
        values.pop(key, None)
    values.update(overrides)
    target = source.__class__.objects.create(**values)
    timestamps = {key: getattr(source, key) for key in ('created_at', 'updated_at') if hasattr(source, key)}
    if hasattr(source, 'updated_by_id'):
        timestamps['updated_by_id'] = source.updated_by_id
    if timestamps:
        source.__class__.objects.filter(pk=target.pk).update(**timestamps)
    return target


def remap_prediction_snapshot(value, predictions, task):
    value = copy.deepcopy(value)
    if isinstance(value, list):
        return [remap_prediction_snapshot(item, predictions, task) for item in value]
    if isinstance(value, dict) and 'result' in value:
        old_id = value.pop('id', None)
        if old_id in predictions:
            value['id'] = predictions[old_id].pk
        for key in ('task', 'task_id'):
            if key in value:
                value[key] = task.pk
        for key in ('project', 'project_id'):
            if key in value:
                value[key] = task.project_id
        if 'neighbors' in value:
            value['neighbors'] = None
    return value


class ProjectCopyTaskAPI(APIView):
    def get(self, request, pk, job_id, task_id):
        session = get_session(request, pk, job_id)
        link = session.copied_tasks.filter(source_task_id=task_id).first()
        if link:
            if not link.target_task_id:
                raise ValidationError('Copied task was deleted')
            return Response({'target_task': link.target_task_id})
        task = get_object_or_404(Task, pk=task_id, project_id=pk, id__lte=session.source_max_task_id)
        payload = snapshot(task)
        payload['label_config'] = session.configuration['label_config']
        payload['media_url'] = download_url(task, payload['data'].get(media_key(payload['label_config'])))
        return Response(payload)

    @transaction.atomic
    def post(self, request, pk, job_id, task_id):
        session = get_session(request, pk, job_id, lock=True)
        old = session.copied_tasks.filter(source_task_id=task_id).first()
        if old:
            if not old.target_task_id:
                raise ValidationError('Copied task was deleted')
            return Response({'target_task': old.target_task_id})
        source = get_object_or_404(Task.objects.select_for_update(), pk=task_id, project_id=pk, id__lte=session.source_max_task_id)
        current = snapshot(source)
        if request.data.get('revision') != current['revision']:
            raise ValidationError('Source task or annotations changed during copy; retry this task')
        if source.project.label_config != session.configuration['label_config']:
            raise ValidationError('Source labeling configuration changed')
        storage = get_object_or_404(S3ImportStorage, pk=session.storage_id, project_id=session.target_project_id)
        key = request.data.get('key', '')
        media = media_key(session.configuration['label_config'])
        data = request.data.get('data')
        if key not in (storage.prefix + '/' + str(task_id) + '.png', storage.prefix + '/' + str(task_id) + '.mp4'):
            raise ValidationError('Unexpected destination object key')
        expected = copy.deepcopy(current['data'])
        expected[media] = f's3://{storage.bucket}/{key}'
        if data != expected:
            raise ValidationError('Only the media URL may change in task data')
        groups = {}
        for name in ('annotations', 'predictions', 'drafts'):
            records = request.data.get(name)
            if not isinstance(records, list) or any(not isinstance(item, dict) or not isinstance(item.get('result'), list) for item in records):
                raise ValidationError('Invalid transformed ' + name)
            groups[name] = {item.get('id'): item for item in records}
            if len(groups[name]) != len(records) or set(groups[name]) != {item['id'] for item in current[name]}:
                raise ValidationError('Transformed result IDs do not match the source task')
        target = Task.objects.create(project_id=session.target_project_id, data=data, meta=copy.deepcopy(source.meta),
                                     overlap=source.overlap, updated_by=source.updated_by)
        predictions, annotations = {}, {}
        for old_prediction in source.predictions.all():
            predictions[old_prediction.pk] = clone_record(old_prediction, {'task_id', 'project_id', 'neighbors'},
                task_id=target.pk, project_id=session.target_project_id, neighbors=None,
                result=groups['predictions'][old_prediction.pk]['result'])
        for old_annotation in source.annotations.all():
            transformed = groups['annotations'][old_annotation.pk]
            parent = predictions.get(old_annotation.parent_prediction_id)
            annotations[old_annotation.pk] = clone_record(old_annotation,
                {'task_id', 'project_id', 'unique_id', 'parent_annotation_id', 'parent_prediction_id'},
                task_id=target.pk, project_id=session.target_project_id, parent_prediction_id=parent.pk if parent else None,
                parent_annotation_id=None, result=transformed['result'], result_count=len(transformed['result']),
                prediction=remap_prediction_snapshot(transformed.get('prediction', {}), predictions, target))
        for old_annotation in source.annotations.all():
            if old_annotation.parent_annotation_id in annotations:
                Annotation.objects.filter(pk=annotations[old_annotation.pk].pk).update(
                    parent_annotation_id=annotations[old_annotation.parent_annotation_id].pk)
        for old_draft in source.drafts.all():
            parent = annotations.get(old_draft.annotation_id)
            clone_record(old_draft, {'task_id', 'annotation_id'}, task_id=target.pk,
                         annotation_id=parent.pk if parent else None, result=groups['drafts'][old_draft.pk]['result'])
        S3ImportStorageLink.create(target, key, storage)
        ProjectCopyTask.objects.create(session=session, source_task_id=task_id, target_task=target)
        return Response({'target_task': target.pk}, status=201)
