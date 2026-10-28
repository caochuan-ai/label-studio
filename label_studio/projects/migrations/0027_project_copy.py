from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('projects', '0026_auto_20231103_0020'),
        ('tasks', '0045_auto_20231124_1238'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(name='ProjectCopySession', fields=[
            ('id', models.UUIDField(primary_key=True, editable=False, serialize=False)),
            ('source_max_task_id', models.BigIntegerField(default=0)),
            ('configuration', models.JSONField(default=dict)),
            ('storage_id', models.IntegerField(null=True)),
            ('created_at', models.DateTimeField(auto_now_add=True)),
            ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ('source_project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='copy_sessions', to='projects.project')),
            ('target_project', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='copied_from_sessions', to='projects.project')),
        ]),
        migrations.CreateModel(name='ProjectCopyTask', fields=[
            ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('source_task_id', models.BigIntegerField()),
            ('session', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='copied_tasks', to='projects.projectcopysession')),
            ('target_task', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='tasks.task')),
        ]),
        migrations.AddConstraint(model_name='projectcopytask', constraint=models.UniqueConstraint(fields=('session', 'source_task_id'), name='unique_project_copy_task')),
    ]
