import pickle

from typing import List, Tuple
from model.settings import Settings


class Project():
    def __init__(self, name: str, settings: Settings):
        self.name = name
        self.settings: Settings = settings


class Storage():
    def __init__(self):
        self.data: List[Project] = self.get_data()

    def get_project(self, name):
        for project in self.data:
            if project.name == name:
                return project
        return None
    
    def add_project(self, project):
        self.data.append(project)
        self.save_data()

    def get_data(self):
        with open("app/data.pickle", "rb") as f:
            data = f.read()
            data = pickle.loads(data)
        return data

    def save_data(self):
        with open("app/data.pickle", "wb") as f:
            f.write(pickle.dumps(self.data))

storage = Storage()