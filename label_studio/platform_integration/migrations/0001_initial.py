from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('organizations', '0006_alter_organizationmember_deleted_at'),
        ('projects', '0026_auto_20231103_0020'),
    ]
    operations = [
        migrations.CreateModel(
            name='PlatformUserIdentity',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('external_user_id', models.CharField(max_length=128, unique=True)),
                ('scope', models.CharField(choices=[('platform', 'Platform'), ('tenant', 'Tenant')], max_length=16)),
                ('external_tenant_id', models.CharField(blank=True, db_index=True, default='', max_length=128)),
                ('platform_session_id', models.CharField(blank=True, default='', max_length=256)),
                ('claims', models.JSONField(blank=True, default=dict)),
                ('checked_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='platform_identity', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PlatformOrganizationBinding',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('external_tenant_id', models.CharField(max_length=128, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('organization', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='platform_binding', to='organizations.organization')),
            ],
        ),
        migrations.CreateModel(
            name='PlatformProjectBinding',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('external_tenant_id', models.CharField(db_index=True, max_length=128)),
                ('external_dataset_id', models.CharField(max_length=128, unique=True)),
                ('active', models.BooleanField(db_index=True, default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('project', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='platform_binding', to='projects.project')),
            ],
            options={'indexes': [models.Index(fields=['external_tenant_id', 'active'], name='platform_in_externa_967c6a_idx')]},
        ),
    ]
