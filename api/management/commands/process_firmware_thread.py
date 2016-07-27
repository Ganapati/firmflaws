import sys
import threading
from django.core.management import call_command

class ProcessFirmwareThread(threading.Thread):
    def __init__(self):
        super(ProcessFirmwareThread, self).__init__()
    def run(self): 
        call_command('process_firmware')


def start_process_thread():
    thread = ProcessFirmwareThread()
    thread.start()