# Generated by Django 4.2.20 on 2025-04-04 04:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0003_alter_user_groups_alter_user_user_permissions'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('staff', 'Staff'), ('customer', 'Customer')], default='customer', max_length=10),
        ),
    ]
