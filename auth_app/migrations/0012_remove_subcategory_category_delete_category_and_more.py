# Generated by Django 5.1.1 on 2024-10-07 16:28

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0011_category_subcategory'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='subcategory',
            name='category',
        ),
        migrations.DeleteModel(
            name='Category',
        ),
        migrations.DeleteModel(
            name='SubCategory',
        ),
    ]
