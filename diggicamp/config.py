import json
import diggicamp


CONFIG_VERSION = "1.1.0"


class DiggicampConf:

    def __init__(self, settings: object):
        self.opts = settings

        if 'version' not in settings or settings['version'] != CONFIG_VERSION:
            print("different version detected")
            diggicamp.migrate_config(self)

    def get(self, key: str) -> str:
        obj = self.opts
        for path in key.split("."):
            if path in obj:
                obj = obj[path]
            else:
                return None
        return obj

    def set(self, key: str, val: any):
        keys = key.split(".")
        lastKey = keys[len(keys)-1]
        obj = self.opts
        for path in keys[:len(keys)-1]:
            if not path in obj:
                obj[path] = {}
            obj = obj[path]
        obj[lastKey] = val

    def save(self, file: str):
        with open(file, "w") as f:
            f.write(json.dumps(self.opts, indent=2))

    def has(self, key: str):
        obj = self.opts
        for path in key.split("."):
            if path in obj:
                obj = obj[path]
            else:
                return False
        return True

    def add_auth(self, mode, **args):
        args['mode'] = mode
        self.set('credentials', args)

    def version(self):
        return self.get('version')

    @staticmethod
    def fromFile(fname: str) -> 'DiggicampConf':
        with open(fname, "r") as f:
            return DiggicampConf(json.load(f))

    @staticmethod
    def fromString(string: str) -> 'DiggicampConf':
        return DiggicampConf(json.loads(string))

    @staticmethod
    def default(url: str) -> 'DiggicampConf':
        conf = DiggicampConf({'version': CONFIG_VERSION})
        conf.set('baseurl', url)
        return conf
