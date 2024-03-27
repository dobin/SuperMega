import pickle
import os
import yaml

from typing import List, Tuple
from model.settings import Settings
from model.defs import *

class Project():
    def __init__(self, name: str, settings: Settings):
        self.name = name
        self.settings: Settings = settings


class Storage():
    def __init__(self):
        self.data: List[Project] = self.get_data()

    def get_project(self, name: str) -> Project:
        for project in self.data:
            if project.name == name:
                return project
        return None
    
    def add_project(self, project: Project):
        # data
        self.data.append(project)
        self.save_data()

        # directories and contents
        os.makedirs(PATH_WEB_PROJECT + project.name, exist_ok=True)
        with open("{}/{}/settings.yaml".format(PATH_WEB_PROJECT, project.name), "w") as f:
            f.write(yaml.dump(project.settings))

    def get_data(self) -> List[Project]:
        # if file does not exist, create an empty one
        if not os.path.exists("app/data.pickle"):
            with open("app/data.pickle", "wb") as f:
                f.write(pickle.dumps([]))

        with open("app/data.pickle", "rb") as f:
            data_raw = f.read()
            data: List[Project] = pickle.loads(data_raw)
        return data

    def save_data(self):
        with open("app/data.pickle", "wb") as f:
            f.write(pickle.dumps(self.data))

storage = Storage()