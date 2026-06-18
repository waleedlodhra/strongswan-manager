"""
server_connections models have been unified into the connections app (Phase 1).
This migration is a no-op placeholder so Django does not complain about a
missing initial migration for this app.
"""
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('connections', '0003_unified_model'),
    ]
    operations = []
