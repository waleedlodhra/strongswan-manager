from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('certificates', '0002_update_encrypted_fields'),
    ]

    operations = [
        migrations.CreateModel(
            name='Authority',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('name', models.TextField(unique=True)),
                ('cacert', models.TextField(blank=True, default='')),
                ('crl_uris', models.TextField(blank=True, default='')),
                ('ocsp_uris', models.TextField(blank=True, default='')),
                ('cert_uri_base', models.TextField(blank=True, default='')),
                ('source_file', models.CharField(blank=True, default='', max_length=512)),
                ('cacert_ref', models.ForeignKey(
                    blank=True, default=None, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='authority_configs',
                    to='certificates.usercertificate',
                )),
            ],
        ),
    ]
