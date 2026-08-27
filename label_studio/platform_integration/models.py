from django.conf import settings
from django.db import models


class PlatformUserIdentity(models.Model):
    SCOPE_PLATFORM = 'platform'
    SCOPE_TENANT = 'tenant'
    SCOPE_CHOICES = ((SCOPE_PLATFORM, 'Platform'), (SCOPE_TENANT, 'Tenant'))

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='platform_identity',
    )
    external_user_id = models.CharField(max_length=128, unique=True)
    scope = models.CharField(max_length=16, choices=SCOPE_CHOICES)
    external_tenant_id = models.CharField(max_length=128, blank=True, default='', db_index=True)
    platform_session_id = models.CharField(max_length=256, blank=True, default='')
    claims = models.JSONField(default=dict, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class PlatformOrganizationBinding(models.Model):
    organization = models.OneToOneField(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='platform_binding',
    )
    external_tenant_id = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class PlatformProjectBinding(models.Model):
    project = models.OneToOneField(
        'projects.Project',
        on_delete=models.CASCADE,
        related_name='platform_binding',
    )
    external_tenant_id = models.CharField(max_length=128, db_index=True)
    external_dataset_id = models.CharField(max_length=128, unique=True)
    active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=['external_tenant_id', 'active'])]
