"""User-authenticated queue and heartbeat, with no app-side worker configuration."""
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from projects.copy_api import CopySessionSerializer, CopyStorageSerializer, media_key, source_project
from projects.models import Project, ProjectCopyJob, ProjectCopySession, ProjectCopyWorker
from rest_framework import serializers
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView

HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 30


def lock_owner(user):
    # One queue lock per authenticated user, also serializes duplicate submissions/claims.
    get_user_model().objects.select_for_update().get(pk=user.pk)


def worker_status(user):
    now = timezone.now()
    last = ProjectCopyWorker.objects.filter(created_by=user).order_by('-last_seen').first()
    age = (now - last.last_seen).total_seconds() if last else None
    return {'ready': age is not None and age <= HEARTBEAT_TIMEOUT,
            'last_heartbeat': last.last_seen.timestamp() if last else None,
            'server_time': now.timestamp(), 'timeout': HEARTBEAT_TIMEOUT, 'interval': HEARTBEAT_INTERVAL}


def public_job(job):
    progress = job.progress
    target = ProjectCopySession.objects.filter(pk=job.pk).values_list('target_project_id', flat=True).first()
    last_seen = job.worker.last_seen if job.worker_id else None
    return {
        'id': str(job.pk), 'project': job.source_project_id, 'status': job.status, 'attempt': job.attempt,
        'new_project_name': job.configuration['new_project_name'], 'crop': job.configuration['crop'],
        'created': job.created_at.timestamp(), 'updated': job.updated_at.timestamp(), 'target_project': target,
        'worker_ready': bool(last_seen and (timezone.now() - last_seen).total_seconds() <= HEARTBEAT_TIMEOUT),
        'phase': progress.get('phase', 'queued'), 'total': progress.get('total', 0),
        'completed': progress.get('completed', 0), 'failed': progress.get('failed', 0),
        'current_task': progress.get('current_task'), 'file_progress': progress.get('file_progress', 0),
        'progress': 100 if job.status == 'success' else (
            100 * (progress.get('completed', 0) + progress.get('failed', 0)) / progress['total'] if progress.get('total') else 0),
        'error': progress.get('error'), 'errors': progress.get('errors', []),
    }


class CopyJobSerializer(serializers.Serializer):
    new_project_name = serializers.CharField(max_length=200)
    crop = serializers.DictField(child=serializers.IntegerField(min_value=0))
    source_storage = CopyStorageSerializer()
    idempotency_key = serializers.UUIDField(required=False)
    validate_crop = CopySessionSerializer.validate_crop


class ProjectCopyJobsAPI(APIView):
    def get(self, request, pk, job_id=None):
        source_project(request, pk)
        jobs = ProjectCopyJob.objects.filter(created_by=request.user, source_project_id=pk).select_related('worker')
        if job_id:
            return Response(public_job(get_object_or_404(jobs, pk=job_id)))
        try:
            offset = max(0, int(request.query_params.get('offset', 0)))
        except (TypeError, ValueError):
            raise ValidationError('Invalid history offset')
        return Response({'jobs': [public_job(job) for job in jobs.order_by('-created_at')[offset:offset + 50]],
                         'worker': worker_status(request.user)})

    @transaction.atomic
    def post(self, request, pk, job_id=None):
        source = source_project(request, pk)
        lock_owner(request.user)
        if job_id:
            job = get_object_or_404(ProjectCopyJob.objects.select_for_update(), pk=job_id,
                                    source_project=source, created_by=request.user)
            if job.status != 'fail':
                raise ValidationError('Only failed copy jobs can be retried')
            job.attempt += 1
            job.status = 'waiting'
            job.worker = None
            job.progress = dict(job.progress, phase='queued', error=None, errors=[], failed=0)
            job.save()
        else:
            serializer = CopyJobSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            config = dict(serializer.validated_data)
            key = config.pop('idempotency_key', None) or uuid4()
            media_key(source.label_config)
            job = ProjectCopyJob.objects.filter(pk=key).first()
            if job:
                if job.created_by_id != request.user.pk or job.source_project_id != pk or job.configuration != config:
                    raise ValidationError('Idempotency key already used with different configuration')
            else:
                job = ProjectCopyJob.objects.create(id=key, source_project=source, created_by=request.user, configuration=config)
        return Response(public_job(job), status=202)


class ItemErrorSerializer(serializers.Serializer):
    source = serializers.IntegerField(min_value=1)
    error = serializers.CharField(max_length=1000)


class ProgressSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    attempt = serializers.IntegerField(min_value=1)
    status = serializers.ChoiceField(choices=['waiting', 'copying', 'success', 'fail'])
    phase = serializers.CharField(max_length=50)
    total = serializers.IntegerField(min_value=0)
    completed = serializers.IntegerField(min_value=0)
    failed = serializers.IntegerField(min_value=0)
    current_task = serializers.IntegerField(min_value=1, allow_null=True, default=None)
    file_progress = serializers.FloatField(min_value=0, max_value=1, default=0)
    error = serializers.CharField(max_length=1000, allow_null=True, allow_blank=True, default=None)
    errors = serializers.ListField(child=ItemErrorSerializer(), max_length=100, default=list)

    def validate(self, data):
        if data['completed'] + data['failed'] > data['total']:
            raise ValidationError('Invalid task counters')
        if data['status'] == 'success' and (data['failed'] or data['completed'] != data['total']):
            raise ValidationError('Successful copy must complete every task')
        return data


class HeartbeatSerializer(serializers.Serializer):
    worker_id = serializers.UUIDField()
    report = ProgressSerializer(required=False, allow_null=True)


class ProjectCopyHeartbeatAPI(APIView):
    authentication_classes = [TokenAuthentication]

    @transaction.atomic
    def post(self, request):
        serializer = HeartbeatSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        body = serializer.validated_data
        lock_owner(request.user)
        worker, _ = ProjectCopyWorker.objects.get_or_create(id=body['worker_id'],
            defaults={'created_by': request.user, 'last_seen': timezone.now()})
        if worker.created_by_id != request.user.pk:
            raise PermissionDenied('Worker belongs to another user')
        worker.last_seen = timezone.now()
        worker.save(update_fields=['last_seen'])
        visible = Project.objects.for_user(request.user).values_list('pk', flat=True)
        jobs = ProjectCopyJob.objects.filter(created_by=request.user, source_project_id__in=visible)
        report = body.get('report')
        if report:
            job = jobs.filter(pk=report['id'], worker=worker, attempt=report['attempt']).first()
            if job and job.status == 'copying':
                job.status = report['status'] if report['status'] in ('success', 'fail') else 'copying'
                job.progress = {key: value for key, value in report.items() if key not in ('id', 'attempt', 'status')}
                job.save()
        # Sticky assignment: an offline worker resumes its job, never duplicates an active encoder.
        job = jobs.filter(worker=worker, status='copying').order_by('created_at').first()
        if not job:
            job = jobs.filter(status='waiting').order_by('created_at').first()
            if job:
                job.status, job.worker = 'copying', worker
                job.save()
        payload = None
        if job:
            payload = {'id': str(job.pk), 'owner': job.created_by_id, 'attempt': job.attempt,
                       'request': dict(job.configuration, project_id=job.source_project_id, idempotency_key=str(job.pk))}
        return Response({'job': payload, 'interval': HEARTBEAT_INTERVAL, 'timeout': HEARTBEAT_TIMEOUT})


def require_assignment(request, pk, job_id, lock=False):
    """Fence old retry attempts and reject callbacks from unassigned workers."""
    query = ProjectCopyJob.objects.select_for_update() if lock else ProjectCopyJob.objects
    job = get_object_or_404(query, pk=job_id, source_project_id=pk, created_by=request.user)
    if (job.status != 'copying' or str(job.worker_id) != request.headers.get('X-Copy-Worker') or
            str(job.attempt) != request.headers.get('X-Copy-Attempt')):
        raise PermissionDenied('Copy job is not assigned to this worker attempt')
    return job
