# Generated by Django 2.1.7 on 2019-03-15 13:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('caronte_server', '0002_user_iv'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='joined',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.CharField(max_length=200, unique=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='last_login',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
