from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
from django.db import IntegrityError
from django.conf import settings
from django.db.models import Q
from api.models import FirmwareModel, FileModel, LootModel, BrandModel, LootTypeModel
from lib.parseELF import is_elf, parse_elf
from lib.util import parseFilesToHierarchy
import hashlib
import string
import json
import os

@csrf_exempt
def upload(request):
    """ Upload firmware to firmflaws
    """
    if not request.method == 'POST':
        return JsonResponse({"error": "POST only"})

    if not 'file' in request.FILES:
        return JsonResponse({"error": "No file"})

    description = request.POST['description']
    brand = request.POST['brand']
    version = request.POST['version']
    model = request.POST['model']
    firmware = request.FILES['file']

    brand_obj = BrandModel()
    brand_obj.name = brand
    try:
        brand_obj.save()
    except IntegrityError:
        brand_obj = BrandModel.objects.get(name=brand)

    content = firmware.read()
    hash = hashlib.md5(content).hexdigest()
    directory = os.path.join(settings.FIRMWARES_FOLDER, hash)

    if not os.path.exists(directory):
        os.makedirs(directory)

    path = os.path.join(directory, "firmware")
    with open(path, "wb") as fd:
        fd.write(content)

    firmware_obj = FirmwareModel()
    firmware_obj.brand = brand_obj
    firmware_obj.description = description
    firmware_obj.version = version
    firmware_obj.model = model
    firmware_obj.name = firmware.name
    firmware_obj.filesize = firmware.size
    firmware_obj.hash = hash
    firmware_obj.filepath = path

    try:
        firmware_obj.save()
        return JsonResponse({"status": "new", "hash": firmware_obj.hash})
    except IntegrityError:
        return JsonResponse({"status": "repost", "hash": firmware_obj.hash})

def get_firmware(request, hash):
    """ Return firmware informations
    """
    try:
        firmware = FirmwareModel.objects.get(hash=hash)

        # Direct download
        if 'raw' in request.GET.keys():
            content = ""
            content_type = "application/octet-stream"
            with open(firmware.filepath, "rb") as fd:
                content = fd.read()
            response = HttpResponse(content, content_type=content_type)
            content_disposition = "attachment; filename=%s.img" % firmware.hash
            response["Content-Disposition"] = content_disposition
            return response

        files = []
        for file in firmware.files.all():
            files.append({"filename": file.filename,
                          "size": file.filesize,
                          "type": file.file_type,
                          "hash": file.hash,
                          "nb_loots": file.nb_loots})

        loots = {}
        loots_types = [_.name for _ in LootTypeModel.objects.all()]
        for type in loots_types:
            result = LootModel.objects.filter(type__name=type, file__firmware=firmware).count()
            loots[type] = result

        return JsonResponse({"name": firmware.name,
                             "hash": firmware.hash,
                             "model": firmware.model,
                             "version": firmware.version,
                             "status": firmware.status,
                             "loots": loots,
                             "files": files,
                             "filesize": firmware.filesize,
                             "brand": firmware.brand.name,
                             "description": firmware.description})

    except FirmwareModel.DoesNotExist:
        return JsonResponse({"error": "firmware not found", "hash": hash})

def get_hierarchy(request, hash):
    try:
        firmware = FirmwareModel.objects.get(hash=hash)

        files = []
        for file in firmware.files.all():
            files.append({"filename": file.filename,
                          "size": file.filesize,
                          "type": file.file_type,
                          "hash": file.hash,
                          "nb_loots": file.nb_loots})

        loots = {}
        loots_types = [_.name for _ in LootTypeModel.objects.all()]
        for type in loots_types:
            result = LootModel.objects.filter(type__name=type, file__firmware=firmware).count()
            loots[type] = result

        #maybe let's keep this in db?
        mytree = parseFilesToHierarchy(files)
        return JsonResponse({"name": firmware.name,
                             "hash": firmware.hash,
                             "model": firmware.model,
                             "version": firmware.version,
                             "status": firmware.status,
                             "loots": loots,
                             "hierarchy": mytree,
                             "filesize": firmware.filesize,
                             "brand": firmware.brand.name,
                             "description": firmware.description})
    except FirmwareModel.DoesNotExist:
        return JsonResponse({"error": "firmware not found", "hash": hash})


def get_file(request, hash):
    """ Return file from given hash
    """
    try:
        file = FileModel.objects.get(hash=hash)
        content = ""
        with open(file.filepath, "rb") as fd:
            content = fd.read()
        # Direct download
        if 'raw' in request.GET.keys():
            content = ""
            with open(file.filepath, "rb") as fd:
                content = fd.read()
            content_type = "application/octet-stream"
            response = HttpResponse(content, content_type=content_type)
            content_disposition = "attachment; filename=%s" % file.filename
            response["Content-Disposition"] = content_disposition
            return response

        # Graph download
        if 'graph' in request.GET.keys():
            if file.graph_file != "":
                content = ""
                with open(file.graph_file, "rb") as fd:
                    content = fd.read()

                content_type = "image/png"
                response = HttpResponse(content, content_type=content_type)
                return response
            else:
                return HttpResponse("no graph")

        loots = []
        for loot in file.loots.all():
            loots.append({"type": loot.type.name, "info": loot.info})

        response = {"loots": loots,
                    "hash": file.hash,
                    "type": file.file_type,
                    "filename": file.filename,
                    "informations": file.informations,
                    "filesize": file.filesize}
        if is_elf(file):
            response["imports"] = file.imports
            response["graph"] = True
            if file.graph_file == "":
                workspace = file.firmware.all()[0].filepath.replace("firmware",
                                                                    "")
                parse_elf(workspace, file)

        if "ASCII text" in file.file_type:
            content = ""
            with open(file.filepath, "r") as fd:
                content = fd.read()
            response["content"] = content

        return JsonResponse(response)
    except FileModel.DoesNotExist:
        return JsonResponse({"error": "file not found", "hash": hash})

def get_latest(request):
    """ Return the 10 last firmwares
    """
    try:
        firmwares = FirmwareModel.objects.all().order_by('-id')[:10]
        response = []
        for firmware in firmwares:
            response.append({"name": firmware.name,
                             "hash": firmware.hash,
                             "version": firmware.version,
                             "status": firmware.status,
                             "filesize": firmware.filesize,
                             "brand": firmware.brand.name,
                             "description": firmware.description,
                             "model": firmware.model})
        return JsonResponse({"firmwares": response})
    except:
        return JsonResponse({"error": "unknown error"})

def get_stats(request):
    """ Return global stats
    """
    try:
        response = {"total": LootModel.objects.all().count()}
        loots_types = [_.name for _ in LootTypeModel.objects.all()]
        for type in loots_types:
            result = LootModel.objects.filter(type__name=type).count()
            response[type] = result

        nb_firmwares = FirmwareModel.objects.all().count()
        return JsonResponse({"firmwares": nb_firmwares,
                             "stats_loots": response})
    except:
        return JsonResponse({"error": "unknown error"})

def search(request):
    try:
        k = request.GET.get('keyword', False)
        if k is False:
            return JsonResponse({"Error": "missing keyword argument"})

        firmwares = FirmwareModel.objects.filter(Q(name__icontains=k) |
                                                 Q(description__icontains=k) |
                                                 Q(brand__name__icontains=k)).values("hash", "description", "brand__name", "name")
        response = []
        for firmware in firmwares:
            response.append({"hash": firmware["hash"],
                             "brand": firmware["brand__name"],
                             "name": firmware["name"],
                             "description": firmware["description"]})
        return JsonResponse({"results": response})

    except NotImplementedError:
        return JsonResponse({"Error": "unknown error"})
