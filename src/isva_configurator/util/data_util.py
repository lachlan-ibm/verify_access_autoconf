#!/bin/python 
import os
import yaml

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

    def include(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, CustomLoader)