from django.core.management.base import BaseCommand, CommandError
from api.models import FirmwareModel, FileModel, LootModel, LootTypeModel
from lib.extract import Extractor
from django.conf import settings
from lib.parseELF import insecure_imports, is_elf, binary_informations
import magic
import re
import os
import fnmatch
import shutil
import uuid
import hashlib

class Command(BaseCommand):
    help = 'process firmware'

    def handle(self, *args, **options):
        try:
            self.firmware = FirmwareModel.objects.filter(status="waiting")[0]
            self.workspace = self.firmware.filepath.replace("firmware", "")
            self.set_status("0")

            extractor = Extractor(self.workspace, self.firmware.filepath)
            self.extracted_path = extractor.extract()
            self.set_status("50")
            self.register_files()
            self.set_status("done")
        except IndexError:
            self.stdout.write("No waiting firmwares")

    def register_files(self):
        print("Start registering files")
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                full_path = os.path.join(root, file)
                if not os.path.isfile(full_path):
                    continue
                path = full_path.replace(self.extracted_path, "")
                content = ""
                hash = ""
                with open(full_path, "rb") as fd:
                    content = fd.read()
                    hash_content = "%s:%s" % (file, content)
                    hash = hashlib.md5(hash_content.encode('utf-8')).hexdigest()
                try:
                    file_obj = FileModel.objects.get(hash=hash)
                    file_obj.firmware.add(self.firmware)
                    file_obj.save()
                except FileModel.DoesNotExist:
                    file_obj = FileModel()
                    file_obj.filepath = os.path.join(root, file)
                    file_obj.hash = hash
                    file_obj.filesize = len(content)
                    file_obj.filename = path
                    file_obj.save()
                    file_obj.firmware.add(self.firmware)
                    try:
                        file_obj.file_type = magic.from_file(os.path.join(root,
                                                                          file))
                    except:
                        file_obj.file_type = "unknown"
                    file_obj.save()
                    self.find_loots(file_obj)

        print("Files registered")

    def find_loots(self, file):
        # Find loots based on filenames
        loots_refs = settings.LOOTS_FILENAMES
        for type, values in loots_refs.items():
            try:
                loot_type = LootTypeModel.objects.get(name=type)
                loot_type.save()
            except LootTypeModel.DoesNotExist:
                loot_type = LootTypeModel()
                loot_type.name = type
                loot_type.save()
            for value in values:
                if fnmatch.fnmatch(file.filename, value):
                    loot = LootModel()
                    loot.file = file
                    loot.type = loot_type
                    loot.info = "Filename looks interesting"
                    loot.save()

        # Find greppable loots
        loots_refs = settings.LOOTS_GREP
        
        with open(file.filepath, "rb") as fd:
            content = fd.read()

        for type, values in loots_refs.items():
            try:
                loot_type = LootTypeModel.objects.get(name=type)
            except LootTypeModel.DoesNotExist:
                loot_type = LootTypeModel()
                loot_type.name = type
                loot_type.save()
            for value in values:
                if re.search(str.encode(value), content, re.IGNORECASE):
                    loot = LootModel()
                    loot.file = file
                    loot.type = loot_type
                    loot.info = "find %s in file" % value
                    loot.save()

        if is_elf(file):
            insecure_imports(file)
            binary_informations(file)

    def set_status(self, status):
        self.firmware.status = status
        self.firmware.save()
