# Generated by Django 5.1.1 on 2024-10-28 13:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0017_user_qrcode'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='qrcode',
            field=models.ImageField(blank=True, null=True, upload_to='qrcodes/'),
        ),
    ]
