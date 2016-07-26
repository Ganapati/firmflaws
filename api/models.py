from __future__ import unicode_literals

from django.db import models


class BrandModel(models.Model):
    name = models.CharField(unique=True, max_length=255)

class FirmwareModel(models.Model):
    brand = models.ForeignKey(BrandModel, related_name="firmwares")
    hash = models.CharField(unique=True, max_length=32)
    status = models.CharField(max_length=20, default="waiting")
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    model = models.CharField(max_length=255)
    filepath = models.CharField(max_length=255)
    version = models.CharField(max_length=255)
    filesize = models.IntegerField()

class FileModel(models.Model):
    firmware = models.ManyToManyField(FirmwareModel, related_name="files")
    hash = models.CharField(unique=True, max_length=32)
    filename = models.CharField(max_length=255)
    filepath = models.CharField(max_length=255)
    filesize = models.IntegerField()
    graph_file = models.CharField(max_length=255,
                                  default="",
                                  null=True,
                                  blank=True)
    imports = models.TextField()
    informations = models.TextField()
    file_type = models.TextField()
    nb_loots = models.IntegerField(default=0)

class LootTypeModel(models.Model):
    name = models.CharField(unique=True, max_length=255)

class LootModel(models.Model):
    file = models.ForeignKey(FileModel, related_name="loots")
    type = models.ForeignKey(LootTypeModel, related_name="loots")
    info = models.TextField(null=True, blank=True)
