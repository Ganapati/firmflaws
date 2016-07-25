import os
from django.conf import settings
import subprocess

def is_parsable(filename):
    """ check if file is parsable by rats
    """
    
    filename, file_extension = os.path.splitext(filename)
    if file_extension in ['.php', '.pl', '.c', '.cpp', '.py']:
        return True
    return False

def parse(filename):
    """ Do the rats parsing here
    """
    cmd = [settings.RATS_BINARY, "--resultsonly", filename]
    results = subprocess.check_output(cmd)
    results = results.decode("utf-8")
    finds = []
    for line in results.split("\n"):
    	if "High" in line or "Medium" in line:
    		infos = line.split(":")
    		line = infos[1].strip()
    		rank = infos[2].strip()
    		method = infos[3].strip()
    		msg = "%s : %s in line %s" % (rank, method, line)
    		finds.append(msg)
    return finds