import logging

from model import *
from model.defs import *
from model.payload import Payload
from model.exehost import ExeHost


logger = logging.getLogger("Project")


class Project():
    def __init__(self, settings):
        self.settings = settings
        self.payload = Payload(self.settings.payload_path)
        self.exe_host = ExeHost(self.settings.inject_exe_in)


    def init(self):
        self.payload.init()
        self.exe_host.init()
