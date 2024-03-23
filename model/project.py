import logging

from model.payload import Payload
from model.exehost import ExeHost
from model.settings import Settings
from model.carrier import Carrier


logger = logging.getLogger("Project")


class Project():
    def __init__(self, settings: Settings):
        self.name: str = ""
        self.comment: str = ""
        self.settings: Settings = settings
        self.payload: Payload = Payload(self.settings.payload_path)
        self.exe_host: ExeHost = ExeHost(self.settings.inject_exe_in)
        self.carrier: Carrier = Carrier()

        self.project_dir: str = ""
        self.project_exe: str = ""


    def init(self):
        self.payload.init()
        self.exe_host.init()
        self.carrier.init()
