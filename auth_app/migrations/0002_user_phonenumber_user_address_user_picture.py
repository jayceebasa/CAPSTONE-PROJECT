# Generated by Django 5.1.1 on 2024-09-11 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='PhoneNumber',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='address',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='picture',
            field=models.ImageField(blank=True, default='frontend/static/img/default_profpic.png', null=True, upload_to='frontend/static/img'),
        ),
    ]
