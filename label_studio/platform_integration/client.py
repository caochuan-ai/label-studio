import requests
from django.conf import settings


class PlatformClientError(RuntimeError):
    pass


def _headers():
    integration_id = str(getattr(settings, 'PLATFORM_INTEGRATION_ID', '') or '').strip()
    service_token = str(getattr(settings, 'PLATFORM_SERVICE_TOKEN', '') or '').strip()
    if not integration_id or not service_token:
        raise PlatformClientError('平台 SSO 服务凭据未配置。')
    return {
        'Authorization': f'Bearer {service_token}',
        'X-Label-Studio-Integration-ID': integration_id,
        'Content-Type': 'application/json',
    }


def _post(path, payload):
    base_url = str(getattr(settings, 'PLATFORM_API_URL', '') or '').strip().rstrip('/')
    if not base_url:
        raise PlatformClientError('PLATFORM_API_URL 未配置。')
    try:
        response = requests.post(
            f'{base_url}{path}',
            headers=_headers(),
            json=payload,
            timeout=float(getattr(settings, 'PLATFORM_API_TIMEOUT_SECONDS', 5)),
        )
    except requests.RequestException as exc:
        raise PlatformClientError(f'无法连接 ISP 平台: {exc}') from exc
    if not response.ok:
        try:
            detail = response.json().get('detail')
        except (ValueError, AttributeError):
            detail = response.text
        raise PlatformClientError(str(detail or f'ISP 平台返回 HTTP {response.status_code}'))
    return response.json() if response.content else {}


def exchange_code(code):
    return _post('/api/internal/label-studio/sso/exchange/', {'code': code})


def introspect_session(session_id):
    return _post('/api/internal/label-studio/sso/introspect/', {'session_id': session_id})


def revoke_session(session_id):
    return _post('/api/internal/label-studio/sso/revoke/', {'session_id': session_id})
