#!/bin/python 
"""
@copyright: IBM
"""
import os
import yaml
import base64
import kubernetes
import pathlib
from copy import deepcopy
from . import constants as const

def to_camel_case(snake_case):
    parts = snake_case.split('_')
    return parts[0] + ''.join(x.title() for x in parts[1:])

def remap_keys(data_dict, remap_dict):
    '''
    old_dict: dictionary with keys to be remapped
    remap_dict: dictionary with mapping {old_key: new_key}
    '''
    if not isinstance(data_dict, dict) or not isinstance(remap_dict, dict):
        raise TypeError("give me dictionaries")
    return {remap_dict.get(k, k): v for k, v in data_dict.items()}

#Method guaranteed to return a list with at least dictionary in it (if its not empty)
def optional_list(x):
    if isinstance(x, list) and len(x) > 0:
        return x
    else:
        return [{}]

#Filter a list of dicts on a given key for a given value
def filter_list(attribute, value, _list):
    return list(filter(lambda x: attribute in x and x[attribute] == value, _list))

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

    def __deepcopy__(self, memo=None):
        return Map(deepcopy(dict(self), memo=memo)) 


class CustomLoader(yaml.SafeLoader):

    def __init__(self, path):
        self._root = os.path.split(path.name)[0]
        super(CustomLoader, self).__init__(path)
        CustomLoader.add_constructor('!include', CustomLoader.include)
        CustomLoader.add_constructor('!secret', CustomLoader.k8s_secret)
        CustomLoader.add_constructor('!environment', CustomLoader.env_secret)

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

    def env_secret(self, node):
        try:
            return os.environ.get(self.construct_scalar(node))
        except KeyError as e:
            raise ValueError("Environment variable {} does not exist".format(secret)) from e

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
KUBE_CLIENT_SLEEP = 15
try:
    KUBE_CLIENT_SLEEP = int(os.environ.get("ISVA_KUBERNETES_RESTART_SLEEP", 15))
except ValueError:
    KUBE_CLIENT_SLEEP = 15