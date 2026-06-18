from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eap_secrets', '0002_update_encrypted_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='selector_id',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='secret',
            name='owners',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='secret',
            name='source_file',
            field=models.CharField(blank=True, default='', max_length=512),
        ),
        migrations.AlterField(
            model_name='secret',
            name='type',
            field=models.TextField(
                choices=[
                    ('EAP', 'EAP (username/password)'),
                    ('IKE', 'IKE Pre-Shared Key'),
                    ('XAUTH', 'XAUTH credential'),
                    ('ANY', 'Any (legacy ipsec.secrets)'),
                    ('NTLM', 'NTLM'),
                ],
                default='EAP',
            ),
        ),
    ]
