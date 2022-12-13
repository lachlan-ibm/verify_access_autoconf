#!/bin/python 
import os
import yaml
import base64
import kubernetes
import pathlib
from . import constants as const

class Map(dict):
    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for a in args:
            if isinstance(a, dict):
                for k, v in a.items():
                    if isinstance(v, dict):
                        v = Map(v)
                    elif isinstance(v, list):
                        mapList = []
                        for element in v:
                            if isinstance(element, dict) or isinstance(element, list):
                                mapList += [Map(element)]
                            else:
                                mapList += [element]
                        v = mapList
                    self[k] = v
        if kwargs:
            for k, v in kwargs.items():
                if isinstance(v, dict):
                    v = Map(v)
                if isinstance(v, list):
                    kwList = []
                    for element in v:
                        if isinstance(element, dict) or isinstance(element, list):
                            kwList += [Map(element)]
                        else:
                            kwList += [element]
                    v = kwList
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


class CustomLoader(yaml.SafeLoader):

    def __init__(self, path):
        self._root = os.path.split(path.name)[0]
        super(CustomLoader, self).__init__(path)
        CustomLoader.add_constructor('!include', CustomLoader.include)
        CustomLoader.add_constructor('!secret', CustomLoader.k8s_secret)

    def include(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, CustomLoader)

    def k8s_secret(self, node):
        secret = self.construct_scalar(node)
        #Split secret into name and ke
        namespaceName, key = secret.split(':')
        namespace, name = namespaceName.split('/')
        #Use k8s API to look up secret
        k8sSecret = KUBE_CLIENT.CoreV1Api().read_namespaced_secret(name, namespace)
        return base64.b64decode(k8sSecret.data[key]).decode()

class FileLoader():

    def __init__(self, config_base_dir=None):
        self.config_base_dir = config_base_dir if config_base_dir else str(pathlib.Path.home())
        if self.config_base_dir.endswith('/') == False:
            self.config_base_dir += '/'

    def read_files(self, paths, include_directories=False):
        result = []
        if isinstance(paths, str) == True:
            paths = [paths]
        for path in paths:
            result += self.read_file(path, include_directories=include_directories)
        return result

    def read_file(self, path, include_directories=False):
        parsed_files = []
        if not os.path.isabs(path):
            path = self.config_base_dir + path
        if os.path.isdir(path):
            if include_directories == True:
                parsed_files += [{"name": os.path.basename(path), "path": path, "type": "dir", 
                    "directory": os.path.dirname(path).replace(self.config_base_dir, '')}]
            for file_pointer in os.listdir(path):
                parsed_files += [self.read_file(path + file_pointer)]
        else:
            with open(path, 'rb') as _file:
                contents = _file.read()
                result = {"name": os.path.basename(path), "contents": contents, "path": path, "type": "file",
                        "directory": os.path.dirname(path).replace(self.config_base_dir, '')}
                try:
                    result['text'] = contents.decode()
                except Exception:
                    result['text'] = 'undefined'
                parsed_files += [result]
        return parsed_files 

FILE_LOADER = FileLoader(os.environ.get(const.CONFIG_BASE_DIR))

class ISVA_Kube_Client:
    _client = None
    _caught = False

    @classmethod
    def get_client(cls):
        if cls._client == None and cls._caught == False:
            if const.KUBERNETES_CONFIG in os.environ.keys():
                kubernetes.config.load_kube_config(config_file=os.environ.get(const.KUBERNETES_CONFIG))
            elif cls._caught == False:
                try:
                    kubernetes.config.load_config()
                except kubernetes.config.config_exception.ConfigException:
                    cls._caught = True
            cls._client = kubernetes.client
        return cls._client

KUBE_CLIENT = ISVA_Kube_Client.get_client()
