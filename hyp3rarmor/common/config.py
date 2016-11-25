import yaml
import os
from hyp3rarmor.server.constants import HYP3RARMOR_ROOT
from hyp3rarmor.common.exceptions import Hyp3rArmorConfigurationError

class Map(dict):
    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for arg in args:
            if isinstance(arg, dict):
                for k, v in arg.iteritems():
                    self[k] = v

        if kwargs:
            for k, v in kwargs.iteritems():
                self[k] = v

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Map, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Map, self).__delitem__(key)
        del self.__dict__[key]

try:
    with open(os.path.join(HYP3RARMOR_ROOT, "conf/hyp3rarmor.yaml"), "r") as f:
	config = Map(yaml.load(f))
except Exception as e:
    raise Hyp3rArmorConfigurationError(e)

