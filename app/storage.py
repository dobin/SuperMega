import pickle
import os
import yaml
import pickle
import logging

from typing import List, Tuple
from model.defs import *
from model.project import WebProject


logger = logging.getLogger("Storage")

class Storage():
    def __init__(self):
        pass


    def get_projects(self) -> List[WebProject]:
        projects: List[WebProject] = []
        for project_name in os.listdir(PATH_WEB_PROJECT):
            project = self.get_project(project_name)
            if project is None:
                continue
            projects.append(project)
        return projects
    

    def get_project(self, project_name: str) -> WebProject:
        logger.debug("Load project: {}".format(project_name))
        path = "{}/{}".format(PATH_WEB_PROJECT, project_name)
        json_path = "{}/project.pickle".format(path)
        if not os.path.exists(json_path):
            return None
        with open(json_path, "rb") as f:
            project = pickle.load(f)
        return project


    def add_project(self, project: WebProject):
        # directories and contents
        os.makedirs(PATH_WEB_PROJECT + project.name, exist_ok=True)
        with open("{}/{}/project.pickle".format(PATH_WEB_PROJECT, project.name), "wb") as f:
            pickle.dump(project, f)


    def save_project(self, project: WebProject):
        with open("{}/{}/project.pickle".format(PATH_WEB_PROJECT, project.name), "wb") as f:
            pickle.dump(project, f)


storage = Storage()