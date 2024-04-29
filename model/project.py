import logging
import shutil

from model.defs import *
from model.payload import Payload
from model.exehost import ExeHost
from model.settings import Settings
from model.carrier import Carrier

logger = logging.getLogger("Project")


class WebProject():
    def __init__(self, name: str, settings: Settings):
        self.name = name
        self.settings: Settings = settings
        self.comment: str = ""


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


def prepare_project(project_name, settings):
    src = "{}{}/".format(PATH_CARRIER, settings.source_style.value)
    dst = "{}{}/".format(PATH_WEB_PROJECT, project_name)

    # delete all files in dst directory
    for file in os.listdir(dst):
        if file == "project.pickle":
            continue
        if file.startswith("."):
            continue
        if file.endswith(".exe"):
            # keep all exes except:
            if file != "main.exe" and not file.endswith(".infected.exe"):
                continue
        if file.endswith(".dll"):
            # keep all dlls except:
            if not file.endswith(".infected.dll"):
                continue

        os.remove(dst + file)

    # copy *.c *.h files from src directory to dst directory
    for file in os.listdir(src):
        if file.endswith(".c") or file.endswith(".h"):
            logger.info("Copy {} to {}".format(src + file, dst))
            shutil.copy2(src + file, dst)