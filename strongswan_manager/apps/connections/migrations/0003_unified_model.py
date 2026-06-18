"""
Migration 0003: Unified data model.

Extends the connections.Connection and connections.Child models with all
missing StrongSwan / swanctl fields, adds new IKEv1/PSK/XAUTH auth types,
adds AH proposals support, and adds new connection type subclasses.
"""

from django.db import migrations, models
import django.db.models.deletion
import strongswan_manager.helper_apps.encryption.fields


class Migration(migrations.Migration):

    dependencies = [
        ('connections', '0002_update_encrypted_fields'),
        ('pools', '0001_initial'),
    ]

    operations = [
        # ── Connection: new core fields ────────────────────────────────────────
        migrations.AddField(
            model_name='connection',
            name='connection_type',
            field=models.CharField(
                choices=[
                    ('client', 'Client (initiator)'),
                    ('server', 'Server (responder)'),
                    ('site_to_site', 'Site-to-Site'),
                ],
                default='client', max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='connection',
            name='enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='connection',
            name='initiate',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        migrations.AlterField(
            model_name='connection',
            name='version',
            field=models.CharField(
                choices=[('0', 'Any IKE version'), ('1', 'IKEv1'), ('2', 'IKEv2')],
                default='2', max_length=1,
            ),
        ),
        # Pool FK
        migrations.AddField(
            model_name='connection',
            name='pool',
            field=models.ForeignKey(
                blank=True, default=None, null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='connections', to='pools.pool',
            ),
        ),
        # Ports
        migrations.AddField(
            model_name='connection',
            name='local_port',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='connection',
            name='remote_port',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        # Cert handling
        migrations.AddField(
            model_name='connection',
            name='send_certreq',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='connection',
            name='send_cert',
            field=models.CharField(
                choices=[('ifasked', 'ifasked'), ('always', 'always'), ('never', 'never')],
                default='ifasked', max_length=10,
            ),
        ),
        # Timers
        migrations.AddField(model_name='connection', name='rekey_time',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='connection', name='reauth_time',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='connection', name='over_time',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='connection', name='rand_time',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='connection', name='keyingtries',
                            field=models.IntegerField(blank=True, default=None, null=True)),
        # DPD
        migrations.AddField(model_name='connection', name='dpd_delay',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='connection', name='dpd_timeout',
                            field=models.CharField(blank=True, default='', max_length=20)),
        # Behaviour flags
        migrations.AddField(model_name='connection', name='unique',
                            field=models.CharField(blank=True, default='', max_length=10)),
        migrations.AddField(model_name='connection', name='fragmentation',
                            field=models.CharField(blank=True, default='', max_length=10)),
        migrations.AddField(model_name='connection', name='mobike',
                            field=models.BooleanField(blank=True, default=None, null=True)),
        migrations.AddField(model_name='connection', name='encap',
                            field=models.BooleanField(blank=True, default=None, null=True)),
        migrations.AddField(model_name='connection', name='aggressive',
                            field=models.BooleanField(blank=True, default=None, null=True)),
        # XFRM
        migrations.AddField(model_name='connection', name='if_id_in',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='connection', name='if_id_out',
                            field=models.CharField(blank=True, default='', max_length=20)),
        # PPK
        migrations.AddField(model_name='connection', name='ppk_id',
                            field=models.CharField(blank=True, default='', max_length=128)),
        migrations.AddField(model_name='connection', name='ppk_required',
                            field=models.BooleanField(blank=True, default=None, null=True)),
        # Mediation
        migrations.AddField(model_name='connection', name='mediation',
                            field=models.BooleanField(blank=True, default=None, null=True)),
        migrations.AddField(model_name='connection', name='mediated_by',
                            field=models.CharField(blank=True, default='', max_length=128)),
        # DSCP
        migrations.AddField(model_name='connection', name='dscp',
                            field=models.CharField(blank=True, default='', max_length=6)),
        # Source file tracking
        migrations.AddField(model_name='connection', name='source_file',
                            field=models.CharField(blank=True, default='', max_length=512)),
        # Legacy auth text field
        migrations.AlterField(
            model_name='connection',
            name='auth',
            field=models.TextField(blank=True, default=''),
        ),

        # ── Child SA: new fields ───────────────────────────────────────────────
        migrations.AlterField(
            model_name='child',
            name='mode',
            field=models.CharField(
                choices=[('tunnel', 'Tunnel'), ('transport', 'Transport'), ('beet', 'BEET')],
                default='tunnel', max_length=10,
            ),
        ),
        migrations.AddField(
            model_name='child',
            name='start_action',
            field=models.CharField(
                blank=True,
                choices=[('', 'none'), ('start', 'start'), ('trap', 'trap')],
                default=None, max_length=5, null=True,
            ),
        ),
        migrations.AddField(model_name='child', name='close_action',
                            field=models.CharField(blank=True, default='', max_length=10)),
        migrations.AddField(model_name='child', name='dpd_action',
                            field=models.CharField(blank=True, default='', max_length=10)),
        migrations.AddField(model_name='child', name='rekey_time',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='life_time',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='rand_time',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='inactivity',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='mark_in',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='mark_out',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='if_id_in',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='if_id_out',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='copy_df',
                            field=models.BooleanField(blank=True, default=None, null=True)),
        migrations.AddField(model_name='child', name='copy_dscp',
                            field=models.CharField(blank=True, default='', max_length=10)),
        migrations.AddField(model_name='child', name='tfc_padding',
                            field=models.CharField(blank=True, default='', max_length=20)),
        migrations.AddField(model_name='child', name='hw_offload',
                            field=models.CharField(blank=True, default='no', max_length=10)),
        migrations.AddField(model_name='child', name='priority',
                            field=models.IntegerField(blank=True, default=None, null=True)),
        migrations.AddField(model_name='child', name='interface',
                            field=models.CharField(blank=True, default='', max_length=64)),
        migrations.AddField(model_name='child', name='updown',
                            field=models.CharField(blank=True, default='', max_length=512)),

        # ── Proposal: add AH proposals FK ─────────────────────────────────────
        migrations.AddField(
            model_name='proposal',
            name='ah_child',
            field=models.ForeignKey(
                blank=True, default=None, null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='ah_proposals', to='connections.child',
            ),
        ),


        # ── New auth types ─────────────────────────────────────────────────────
        migrations.CreateModel(
            name='PskAuthentication',
            fields=[
                ('authentication_ptr', models.OneToOneField(
                    auto_created=True, on_delete=django.db.models.deletion.CASCADE,
                    parent_link=True, primary_key=True, serialize=False,
                    to='connections.authentication',
                )),
                ('psk_id', models.TextField(blank=True, default='')),
            ],
            bases=('connections.authentication',),
        ),
        migrations.CreateModel(
            name='XauthAuthentication',
            fields=[
                ('authentication_ptr', models.OneToOneField(
                    auto_created=True, on_delete=django.db.models.deletion.CASCADE,
                    parent_link=True, primary_key=True, serialize=False,
                    to='connections.authentication',
                )),
                ('xauth_id', models.TextField(blank=True, default='')),
            ],
            bases=('connections.authentication',),
        ),
        migrations.CreateModel(
            name='EapRadiusAuthentication',
            fields=[
                ('authentication_ptr', models.OneToOneField(
                    auto_created=True, on_delete=django.db.models.deletion.CASCADE,
                    parent_link=True, primary_key=True, serialize=False,
                    to='connections.authentication',
                )),
                ('eap_id', models.TextField(blank=True, default='')),
            ],
            bases=('connections.authentication',),
        ),

        # ── New connection type subclasses ─────────────────────────────────────
        migrations.CreateModel(
            name='IKEv1PSK',
            fields=[
                ('connection_ptr', models.OneToOneField(
                    auto_created=True, on_delete=django.db.models.deletion.CASCADE,
                    parent_link=True, primary_key=True, serialize=False,
                    to='connections.connection',
                )),
            ],
            bases=('connections.connection',),
        ),
        migrations.CreateModel(
            name='IKEv1Certificate',
            fields=[
                ('connection_ptr', models.OneToOneField(
                    auto_created=True, on_delete=django.db.models.deletion.CASCADE,
                    parent_link=True, primary_key=True, serialize=False,
                    to='connections.connection',
                )),
            ],
            bases=('connections.connection',),
        ),
        migrations.CreateModel(
            name='IKEv1XauthPSK',
            fields=[
                ('connection_ptr', models.OneToOneField(
                    auto_created=True, on_delete=django.db.models.deletion.CASCADE,
                    parent_link=True, primary_key=True, serialize=False,
                    to='connections.connection',
                )),
            ],
            bases=('connections.connection',),
        ),
        migrations.CreateModel(
            name='IKEv1XauthCertificate',
            fields=[
                ('connection_ptr', models.OneToOneField(
                    auto_created=True, on_delete=django.db.models.deletion.CASCADE,
                    parent_link=True, primary_key=True, serialize=False,
                    to='connections.connection',
                )),
            ],
            bases=('connections.connection',),
        ),

        # EapTlsAuthentication: add remote_auth field
        migrations.AddField(
            model_name='eaptlsauthentication',
            name='remote_auth',
            field=models.CharField(
                choices=[('eap-tls', 'eap-tls'), ('eap-ttls', 'eap-ttls')],
                default='eap-tls', max_length=56,
            ),
        ),
    ]
