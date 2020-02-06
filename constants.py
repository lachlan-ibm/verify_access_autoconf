import os
import requests
import sys
import time

from pyisam.factory import Factory

CREDS = ("admin", os.environ.get("MGMT_PASSWORD"))

HEADERS = {
            "Content-Type":"application/json",
            "Accept":"application/json"
        }

MGMT_BASE_URL = os.environ.get("MGMT_BASE_URL")
BASE_CODE = os.environ.get("BASE_CODE")
AAC_CODE = os.environ.get("AAC_CODE")
FED_CODE = os.environ.get("FED_CODE")

FACTORY = Factory(MGMT_BASE_URL, CREDS[0], CREDS[1])
WEB = FACTORY.get_web_settings()
AAC = FACTORY.get_access_control()
FED = FACTORY.get_federation()

class Map(dict):
    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for a in args:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    self[k] = v
        if kwargs:
            for k, v in kwargs.items():
                self[k] = v

        def __getattr__(self, attr):
            return self.get(attr, None)

        def __setattr__(self, attr, value):
            self.__setitem__(attr, value)

        def __setitem__(self, k, v):
            super(Map, self).__setitem__(k, v)
            self.__dict__.update({k: v})

        def __delitem__(self, k):
            super(Map, self).__delitem__(k)
            del self.__dict__[k]

CONFIG_BASE_DIR = os.environ.get("CONFIG_BASE_DIR")

class CustomLoader(yaml.SafeLoader):
    def __init__(self, path):
        self._root = os.path.split(path.name)[0]
        super(CustomLoader, self).__init__(path)
        CustomLoader.add_constructor('!include', CustomLoader.include)


    def include(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, CustomLoader)

CONFIG = Map( yaml.load( open(CONFIG_BASE_DIR + '/config.yaml', 'r'), CustomLoader) )


def deploy_pending_changes():
    FACTORY.get_system_settings().configuration.deploy_pending_changes()
