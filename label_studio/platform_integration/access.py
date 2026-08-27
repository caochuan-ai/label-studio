from django.conf import settings


def enabled():
    return bool(getattr(settings, 'PLATFORM_INTEGRATION_ENABLED', False))


def is_service_user(user):
    expected = str(getattr(settings, 'PLATFORM_SERVICE_USER_EMAIL', '') or '').strip().lower()
    return bool(
        expected
        and getattr(user, 'is_authenticated', False)
        and str(getattr(user, 'email', '') or '').strip().lower() == expected
    )


def get_identity(user):
    if not getattr(user, 'is_authenticated', False):
        return None
    try:
        return user.platform_identity
    except Exception:
        return None


def authorized_projects(user, queryset=None):
    from projects.models import Project

    queryset = queryset if queryset is not None else Project.objects.all()
    if not enabled():
        organization_id = getattr(user, 'active_organization_id', None)
        return queryset.filter(organization_id=organization_id)
    if is_service_user(user):
        return queryset
    identity = get_identity(user)
    if identity is None:
        return queryset.none()
    queryset = queryset.filter(platform_binding__active=True)
    if identity.scope == identity.SCOPE_PLATFORM:
        return queryset
    return queryset.filter(platform_binding__external_tenant_id=identity.external_tenant_id)


def project_for_object(obj):
    if obj is None:
        return None
    if obj.__class__.__name__ == 'Project':
        return obj
    project = getattr(obj, 'project', None)
    if project is not None:
        return project
    task = getattr(obj, 'task', None)
    return getattr(task, 'project', None) if task is not None else None


def can_access_project(user, project):
    if project is None:
        return False
    return authorized_projects(user).filter(pk=project.pk).exists()


def is_sso_user(user):
    return get_identity(user) is not None


def assert_platform_managed_mutation(user):
    from rest_framework.exceptions import PermissionDenied

    if enabled() and is_sso_user(user):
        raise PermissionDenied('项目、存储和组织配置只能在 ISP 平台中管理。')
