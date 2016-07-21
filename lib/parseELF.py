from django.conf import settings
from api.models import FileModel
import r2pipe
import os
import pydot

def is_elf(file):
    with open(file.filepath, "rb") as fd:
        head = fd.read(4)
    return (b"\x7FELF" == head)

def parse_elf(workspace, file):
    r2 = r2pipe.open(file.filepath)
    r2.cmd("aa")
    r2.cmd("afl")
    result = r2.cmd("ag $$")
    
    output_dir = os.path.join(workspace, "graphs")
    if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    out_file = os.path.join(output_dir, file.hash)
    graph = pydot.graph_from_dot_data(result)
    graph[0].write_png(out_file)
    file.graph_file = out_file
    file.save()
    print("New graph created")
