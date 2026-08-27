from django.test import TestCase, override_settings
from organizations.models import Organization, OrganizationMember
from projects.models import Project
from rest_framework.test import APIClient
from users.models import User

from .access import authorized_projects, can_access_project
from .models import PlatformOrganizationBinding, PlatformProjectBinding, PlatformUserIdentity


@override_settings(PLATFORM_INTEGRATION_ENABLED=True, PLATFORM_SERVICE_USER_EMAIL='service@example.com')
class PlatformProjectScopeTests(TestCase):
    def setUp(self):
        self.owner_a = User.objects.create_user(email='owner-a@example.com', username='owner-a')
        self.owner_b = User.objects.create_user(email='owner-b@example.com', username='owner-b')
        self.org_a = Organization.create_organization(created_by=self.owner_a, title='Tenant A')
        self.org_b = Organization.create_organization(created_by=self.owner_b, title='Tenant B')
        PlatformOrganizationBinding.objects.create(organization=self.org_a, external_tenant_id='tenant-a')
        PlatformOrganizationBinding.objects.create(organization=self.org_b, external_tenant_id='tenant-b')
        self.project_a = Project.objects.create(title='A', organization=self.org_a, created_by=self.owner_a)
        self.project_b = Project.objects.create(title='B', organization=self.org_b, created_by=self.owner_b)
        PlatformProjectBinding.objects.create(
            project=self.project_a,
            external_tenant_id='tenant-a',
            external_dataset_id='dataset-a',
        )
        PlatformProjectBinding.objects.create(
            project=self.project_b,
            external_tenant_id='tenant-b',
            external_dataset_id='dataset-b',
        )

    def _sso_user(self, email, external_id, scope, tenant_id=''):
        user = User.objects.create_user(email=email, username=email)
        OrganizationMember.objects.create(user=user, organization=self.org_a)
        user.active_organization = self.org_a
        user.save(update_fields=['active_organization'])
        PlatformUserIdentity.objects.create(
            user=user,
            external_user_id=external_id,
            scope=scope,
            external_tenant_id=tenant_id,
            platform_session_id=f'session-{external_id}',
        )
        return user

    def test_tenant_user_sees_only_own_tenant(self):
        user = self._sso_user('tenant@example.com', 'tenant-user', 'tenant', 'tenant-a')
        self.assertEqual(list(authorized_projects(user).values_list('id', flat=True)), [self.project_a.id])
        self.assertTrue(can_access_project(user, self.project_a))
        self.assertFalse(can_access_project(user, self.project_b))

    def test_platform_user_sees_all_active_managed_projects(self):
        user = self._sso_user('platform@example.com', 'platform-user', 'platform')
        self.assertSetEqual(
            set(authorized_projects(user).values_list('id', flat=True)),
            {self.project_a.id, self.project_b.id},
        )

    def test_inactive_binding_is_hidden(self):
        user = self._sso_user('tenant@example.com', 'tenant-user', 'tenant', 'tenant-a')
        binding = self.project_a.platform_binding
        binding.active = False
        binding.save(update_fields=['active'])
        self.assertFalse(authorized_projects(user).exists())

    def test_unbound_local_user_has_no_access_in_platform_mode(self):
        user = User.objects.create_user(email='local@example.com', username='local')
        user.active_organization = self.org_a
        user.save(update_fields=['active_organization'])
        self.assertFalse(authorized_projects(user).exists())


@override_settings(PLATFORM_INTEGRATION_ENABLED=True, PLATFORM_SERVICE_USER_EMAIL='service@example.com')
class ManagedProjectAPITests(TestCase):
    def setUp(self):
        self.service_user = User.objects.create_user(email='service@example.com', username='service')
        self.token = self.service_user.auth_token
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_create_is_idempotent_for_dataset(self):
        payload = {
            'title': 'Tenant A Dataset',
            'external_tenant_id': 'tenant-a',
            'external_dataset_id': 'dataset-a',
        }
        first = self.client.post('/api/platform/projects/', payload, format='json')
        second = self.client.post('/api/platform/projects/', payload, format='json')

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.data['id'], second.data['id'])
        self.assertEqual(PlatformProjectBinding.objects.count(), 1)

    def test_active_project_cannot_be_stolen_by_another_dataset(self):
        created = self.client.post(
            '/api/platform/projects/',
            {
                'title': 'Tenant A Dataset',
                'external_tenant_id': 'tenant-a',
                'external_dataset_id': 'dataset-a',
            },
            format='json',
        )

        response = self.client.post(
            f"/api/platform/projects/{created.data['id']}/bind/",
            {
                'external_tenant_id': 'tenant-a',
                'external_dataset_id': 'dataset-b',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        binding = PlatformProjectBinding.objects.get(project_id=created.data['id'])
        self.assertEqual(binding.external_dataset_id, 'dataset-a')
