from django.conf import settings
from api.models import FileModel, LootModel, LootTypeModel
import r2pipe
import os
import pydot


def open_pipe(file):
    return r2pipe.open(file.filepath)


def is_elf(file):
    with open(file.filepath, "rb") as fd:
        head = fd.read(4)
    return (b"\x7FELF" == head)


def parse_elf(workspace, file):
    r2 = r2pipe.open(file.filepath)
    r2.cmd("aa")
    r2.cmd("afl")
    result = r2.cmd("agC")
    output_dir = os.path.join(workspace, "graphs")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    out_file = os.path.join(output_dir, file.hash)
    graph = pydot.graph_from_dot_data(result)
    graph[0].write_png(out_file)
    file.graph_file = out_file
    file.save()
    print("%s parsed" % file.filepath)


def insecure_imports(file, handle):
    r2 = handle
    imports = "\n".join([_ for _ in r2.cmd("ii").split("\n") if "name=" in _])
    file.imports = imports.replace(settings.FIRMWARES_FOLDER, "")
    file.save()
    type = "potentially insecure function"
    for insecure_function in settings.INSECURE_FUNCTIONS:
        if insecure_function in imports:
            try:
                loot_type = LootTypeModel.objects.get(name=type)
            except LootTypeModel.DoesNotExist:
                loot_type = LootTypeModel()
                loot_type.name = type
                loot_type.save()

            loot = LootModel()
            loot.file = file
            loot.type = loot_type
            loot.info = insecure_function
            loot.save()


def binary_informations(file, handle):
    r2 = handle
    informations = r2.cmd("i")
    file.informations = informations.replace(settings.FIRMWARES_FOLDER, '')
    file.save()
