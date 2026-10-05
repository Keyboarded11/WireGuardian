from django.db import models
from django.contrib.auth.models import User


class Peer(models.Model):
    name = models.CharField(max_length=64)
    public_key = models.CharField(max_length=44, unique=True)
    address = models.GenericIPAddressField(protocol='IPv4', unique=True)
    enabled = models.BooleanField(default=True)
    internet = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)


class Configuration(models.Model):
    endpoint = models.CharField(max_length=253, blank=True)
    revision = models.PositiveIntegerField(default=0)
    applied_revision = models.PositiveIntegerField(default=0)


class Audit(models.Model):
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=80)
    detail = models.CharField(max_length=255, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-id']


class RateBucket(models.Model):
    key = models.CharField(max_length=64, unique=True)
    count = models.PositiveIntegerField(default=0)
    start = models.FloatField()
