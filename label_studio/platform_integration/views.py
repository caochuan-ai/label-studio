import hashlib

from django.conf import settings
from django.contrib.auth import login
from django.db import transaction
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from django.utils import timezone
from organizations.models import Organization, OrganizationMember
from projects.models import Project
from projects.serializers import ProjectSerializer
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from users.models import User

from .access import is_service_user
from .client import PlatformClientError, exchange_code
from .models import PlatformOrganizationBinding, PlatformProjectBinding, PlatformUserIdentity


def _service_user(request):
    if not is_service_user(request.user):
        raise PermissionDenied('Label Studio 平台服务账号无效。')
    return request.user


def _organization_for_tenant(tenant_id, title='ISP Tenant'):
    binding = PlatformOrganizationBinding.objects.select_related('organization').filter(
        external_tenant_id=tenant_id
    ).first()
    if binding:
        return binding.organization
    owner_key = hashlib.sha256(tenant_id.encode('utf-8')).hexdigest()[:24]
    owner_email = f'isp-tenant-owner-{owner_key}@platform.invalid'
    owner, created = User.objects.get_or_create(
        email=owner_email,
        defaults={'username': owner_email, 'is_active': False},
    )
    if created:
        owner.set_unusable_password()
        owner.save(update_fields=['password'])
    organization = Organization.objects.create(title=title, created_by=owner)
    OrganizationMember.objects.get_or_create(user=owner, organization=organization)
    PlatformOrganizationBinding.objects.create(
        organization=organization,
        external_tenant_id=tenant_id,
    )
    return organization


def platform_login(request):
    code = str(request.GET.get('code') or '').strip()
    if not code:
        return HttpResponseBadRequest('缺少一次性登录 code。')
    try:
        claims = exchange_code(code)
    except PlatformClientError as exc:
        return HttpResponseBadRequest(str(exc))

    external_user_id = str(claims.get('user_id') or '').strip()
    scope = str(claims.get('scope') or '').strip()
    tenant_id = str(claims.get('tenant_id') or '').strip()
    if not external_user_id or scope not in {'platform', 'tenant'} or (scope == 'tenant' and not tenant_id):
        return HttpResponseBadRequest('平台返回的账号范围无效。')

    with transaction.atomic():
        identity = PlatformUserIdentity.objects.select_related('user').filter(
            external_user_id=external_user_id
        ).first()
        if identity:
            user = identity.user
        else:
            email = f'isp-{external_user_id}@platform.invalid'
            user = User.objects.create_user(email=email, password=None, username=str(claims.get('username') or email))
            identity = PlatformUserIdentity(user=user, external_user_id=external_user_id)

        user.username = str(claims.get('username') or user.username)
        user.first_name = str(claims.get('first_name') or '')
        user.last_name = str(claims.get('last_name') or '')
        user.is_active = True
        identity.scope = scope
        identity.external_tenant_id = tenant_id if scope == 'tenant' else ''
        identity.platform_session_id = str(claims.get('session_id') or '')
        identity.claims = claims
        identity.checked_at = timezone.now()

        if scope == 'tenant':
            organization = _organization_for_tenant(tenant_id, title=f'ISP Tenant {tenant_id}')
            OrganizationMember.objects.get_or_create(user=user, organization=organization)
            user.active_organization = organization
        elif user.active_organization_id is None:
            organization = Organization.objects.create(title='ISP Platform', created_by=user)
            OrganizationMember.objects.get_or_create(user=user, organization=organization)
            user.active_organization = organization
        user.save(update_fields=['username', 'first_name', 'last_name', 'is_active', 'active_organization'])
        identity.save()

    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    project_id = str(claims.get('project_id') or '').strip()
    prefix = str(getattr(settings, 'FORCE_SCRIPT_NAME', '') or '').rstrip('/')
    if project_id and PlatformProjectBinding.objects.filter(project_id=project_id, active=True).exists():
        return redirect(f'{prefix}/projects/{project_id}/data/')
    return redirect(f'{prefix}/')


class _ServiceAPIView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        _service_user(request)


class ManagedProjectCreateAPIView(_ServiceAPIView):
    def post(self, request):
        tenant_id = str(request.data.get('external_tenant_id') or '').strip()
        dataset_id = str(request.data.get('external_dataset_id') or '').strip()
        title = str(request.data.get('title') or '').strip()
        if not tenant_id or not dataset_id or not title:
            raise ValidationError('external_tenant_id、external_dataset_id 和 title 必填。')
        with transaction.atomic():
            binding = PlatformProjectBinding.objects.select_related('project').filter(
                external_dataset_id=dataset_id
            ).first()
            if binding:
                if binding.external_tenant_id != tenant_id:
                    raise ValidationError('该数据集已绑定到其他租户。')
                binding.active = True
                binding.save(update_fields=['active', 'updated_at'])
                project = binding.project
            else:
                organization = _organization_for_tenant(tenant_id, title=f'ISP Tenant {tenant_id}')
                project = Project.objects.create(
                    title=title,
                    description=str(request.data.get('description') or ''),
                    organization=organization,
                    created_by=request.user,
                )
                PlatformProjectBinding.objects.create(
                    project=project,
                    external_tenant_id=tenant_id,
                    external_dataset_id=dataset_id,
                )
        return Response(ProjectSerializer(project, context={'request': request}).data, status=status.HTTP_200_OK)


class ManagedProjectBindAPIView(_ServiceAPIView):
    def post(self, request, pk):
        tenant_id = str(request.data.get('external_tenant_id') or '').strip()
        dataset_id = str(request.data.get('external_dataset_id') or '').strip()
        if not tenant_id or not dataset_id:
            raise ValidationError('external_tenant_id 和 external_dataset_id 必填。')
        project = Project.objects.filter(pk=pk).first()
        if not project:
            return Response({'detail': 'Project 不存在。'}, status=status.HTTP_404_NOT_FOUND)
        organization = _organization_for_tenant(tenant_id, title=f'ISP Tenant {tenant_id}')
        with transaction.atomic():
            conflict = PlatformProjectBinding.objects.filter(external_dataset_id=dataset_id).exclude(project=project)
            if conflict.exists():
                raise ValidationError('该数据集已绑定到其他 Project。')
            current_binding = PlatformProjectBinding.objects.select_for_update().filter(project=project).first()
            if (
                current_binding
                and current_binding.active
                and current_binding.external_dataset_id != dataset_id
            ):
                raise ValidationError('该 Project 已绑定到其他有效数据集，请先在 ISP 平台停用原数据集。')
            binding, _ = PlatformProjectBinding.objects.update_or_create(
                project=project,
                defaults={
                    'external_tenant_id': tenant_id,
                    'external_dataset_id': dataset_id,
                    'active': True,
                },
            )
            if project.organization_id != organization.id:
                project.organization = organization
                project.save(update_fields=['organization'])
        return Response(ProjectSerializer(binding.project, context={'request': request}).data)


class ManagedProjectDeactivateAPIView(_ServiceAPIView):
    def post(self, request, pk):
        dataset_id = str(request.data.get('external_dataset_id') or '').strip()
        binding = PlatformProjectBinding.objects.filter(project_id=pk, external_dataset_id=dataset_id).first()
        if not binding:
            return Response({'detail': '受管 Project 绑定不存在。'}, status=status.HTTP_404_NOT_FOUND)
        binding.active = False
        binding.save(update_fields=['active', 'updated_at'])
        return Response(status=status.HTTP_204_NO_CONTENT)
