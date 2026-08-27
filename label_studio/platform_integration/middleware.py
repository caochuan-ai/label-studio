from django.contrib.auth import logout
from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone

from .access import enabled, get_identity
from .client import PlatformClientError, introspect_session


class PlatformSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if enabled() and getattr(request.user, 'is_authenticated', False):
            identity = get_identity(request.user)
            if identity is not None:
                path = request.path
                prefix = str(getattr(settings, 'FORCE_SCRIPT_NAME', '') or '').rstrip('/')
                if prefix and path.startswith(prefix):
                    path = path[len(prefix):] or '/'
                if path == '/auth/platform/' or path == '/auth/platform':
                    return self.get_response(request)
                managed_prefixes = (
                    '/api/projects/',
                    '/api/storages/',
                    '/api/import/',
                    '/api/users/',
                    '/api/organizations/',
                    '/api/webhooks/',
                    '/api/ml/',
                )
                if request.method not in {'GET', 'HEAD', 'OPTIONS'} and path.startswith(managed_prefixes):
                    return JsonResponse(
                        {'detail': '项目、任务、存储和组织配置只能在 ISP 平台中管理。'},
                        status=403,
                    )
                if request.method in {'GET', 'HEAD'} and path.startswith('/projects/') and '/settings' in path:
                    return JsonResponse({'detail': '项目配置只能在 ISP 平台中管理。'}, status=403)
                interval = int(getattr(settings, 'PLATFORM_INTROSPECTION_INTERVAL_SECONDS', 60))
                stale = not identity.checked_at or (timezone.now() - identity.checked_at).total_seconds() >= interval
                if request.method not in {'GET', 'HEAD', 'OPTIONS'} or stale:
                    try:
                        claims = introspect_session(identity.platform_session_id)
                        if not claims.get('active'):
                            raise PlatformClientError('平台会话已失效。')
                        identity.scope = str(claims.get('scope') or identity.scope)
                        identity.external_tenant_id = str(claims.get('tenant_id') or '')
                        identity.claims = claims
                        identity.checked_at = timezone.now()
                        identity.save(update_fields=['scope', 'external_tenant_id', 'claims', 'checked_at', 'updated_at'])
                    except PlatformClientError as exc:
                        logout(request)
                        return JsonResponse({'detail': str(exc)}, status=401)
        return self.get_response(request)
