from django.db import migrations

SQL = r"""
DROP TRIGGER IF EXISTS obs_no_update;
CREATE TRIGGER obs_no_update
BEFORE UPDATE ON evidence_observation
BEGIN
  SELECT RAISE(ABORT, 'observations are append-only');
END;

DROP TRIGGER IF EXISTS obs_no_delete;
CREATE TRIGGER obs_no_delete
BEFORE DELETE ON evidence_observation
BEGIN
  SELECT RAISE(ABORT, 'observations are append-only');
END;
"""

class Migration(migrations.Migration):

    dependencies = [
        ('evidence', '0001_initial'),
    ]

    operations = [migrations.RunSQL(SQL)]
