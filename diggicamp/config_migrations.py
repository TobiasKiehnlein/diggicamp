from .config import CONFIG_VERSION, DiggicampConf


"""
This file contains migrations for the config files

Each function MIGRATIONS[<version>] is a migration from <version> to a newer one
the function set's the new version in the settings object. 
"""

# migrate from no version tag to version tag


def migrate_none(conf: DiggicampConf):
    print("Migrating to version 1.1.0...")
    conf.set('version', '1.1.0')

    if not conf.get('downloads'):
        return conf

    old_dl = conf.get('downloads')
    downloads = []
    for fid in old_dl:
        if isinstance(old_dl[fid], str):
            downloads.append({
                'folder': fid,
                'target': old_dl[fid]
            })
        else:
            downloads.append({
                'folder': fid,
                'target': old_dl[fid]['target'],
                'regex': old_dl[fid]['regex']
            })

    conf.set('downloads', downloads)


MIGRATIONS = {
    'None': migrate_none
}


def migrate_config(conf: DiggicampConf):
    while conf.version() != CONFIG_VERSION:
        if conf.version() == None:
            MIGRATIONS['None'](conf)
            continue

        if conf.version() in MIGRATIONS:
            MIGRATIONS[conf.version()](conf)
        else:
            raise Exception("Cannot migrate from " + conf.version() + " - No migration found!")
