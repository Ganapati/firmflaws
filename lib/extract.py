#!/usr/bin/python

import os, sys
import re
import tarfile
import shutil
import subprocess
from lib.extractor import Extractor as FirmadyneExtractor

class Extractor():

    def __init__(self, workspace, input):
        self.input = input
        self.workspace = workspace

    def extract(self):
        candidates = {}
        self.output = os.path.join(self.workspace, "extracted")
        print("Start extract")
        extractor = FirmadyneExtractor(indir=self.input,
                                       outdir=self.output,
                                       rootfs=True,
                                       kernel=True,
                                       numproc=True,
                                       server=None,
                                       brand=None)
        extractor.extract()
        self.process_extraction()
        print("Extract completed")
        return os.path.join(self.workspace, "extracted")

    def process_extraction(self):
        files = os.listdir(self.output)
        for file in files:
            filename, extension = os.path.splitext(file)
            if file.endswith(".kernel"):
                os.remove(os.path.join(self.output, file))
            elif file.endswith(".tar.gz"):
                self.untar(os.path.join(self.output, file),
                           self.output)
                os.remove(os.path.join(self.output, file))

    def untar(self, archive, path):
        with tarfile.open(archive, 'r:gz') as tar:
            for file_ in tar:
                if file_.name in [".", ".."]:
                    continue
                try:
                    tar.extract(file_, path=path)
                except IOError:
                    try:
                        os.remove(path + file_.name)
                        tar.extract(file_, path)
                    except:
                        pass
                finally:
                    try:
                        os.chmod(path + file_.name, file_.mode)
                    except:
                        """ If anyone asks, i've never wrote that
                        """
                        pass
