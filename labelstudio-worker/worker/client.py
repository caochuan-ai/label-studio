import os
from urllib.parse import urlparse

import requests


class LabelStudio:
    def __init__(self, token, project_id=None, worker_id=None, attempt=None):
        self.base = os.environ['LABEL_STUDIO_URL'].rstrip('/')
        if urlparse(self.base).scheme not in ('http', 'https'):
            raise ValueError('LABEL_STUDIO_URL must be HTTP(S)')
        self.token, self.project_id = token, project_id
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers['Authorization'] = 'Token ' + token
        if worker_id:
            self.session.headers['X-Copy-Worker'] = str(worker_id)
            self.session.headers['X-Copy-Attempt'] = str(attempt)

    def call(self, method, path, **kwargs):
        response = self.session.request(method, self.base + '/api/projects/' + str(self.project_id) + '/copy/' + path,
                                        timeout=(10, 60), allow_redirects=False, **kwargs)
        if not response.ok or response.is_redirect:
            # Never include URLs, signed query strings, headers or arbitrary remote response bodies.
            raise RuntimeError('Label Studio bridge returned HTTP ' + str(response.status_code))
        return response.json()

    def heartbeat(self, worker_id, report=None):
        response = self.session.post(self.base + '/api/projects/copy/heartbeat/',
            json={'worker_id': worker_id, 'report': report}, timeout=(3, 5), allow_redirects=False)
        if not response.ok or response.is_redirect:
            raise RuntimeError('Label Studio bridge returned HTTP ' + str(response.status_code))
        return response.json()

    def close(self):
        self.session.close()
