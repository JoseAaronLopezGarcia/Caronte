# Generated by Django 2.1.7 on 2019-03-27 16:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('caronte_server', '0005_auto_20190320_1527'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='last_login',
            new_name='last_active',
        ),
        migrations.AddField(
            model_name='user',
            name='pw_score',
            field=models.IntegerField(default=0),
        ),
    ]
