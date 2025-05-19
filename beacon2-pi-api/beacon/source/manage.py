# Please, name the database as the folder's name inside the connections module.

analyses={
    'granularity': {
        'boolean': True,
        'count': True,
        'record': True
    },
    'singleEntryUrl': True,
    'endpoints': {
        'genomicVariant': True
    },
    'testMode': True,
    'database': 'mongo'
}
biosamples={
    'granularity': {
        'boolean': True,
        'count': True,
        'record': True
    },
    'singleEntryUrl': True,
    'endpoints': {
        'analysis': True,
        'genomicVariant': True,
        'run': True
    },
    'testMode': True,
    'database': 'mongo'
}
cohorts={
    'granularity': {
        'boolean': True,
        'count': True,
        'record': True
    },
    'singleEntryUrl': True,
    'endpoints': {
        'analysis': True,
        'individual': True,
        'run': True
    },
    'testMode': True,
    'database': 'mongo'
}
datasets={
    'granularity': {
        'boolean': True,
        'count': True,
        'record': True
    },
    'singleEntryUrl': True,
    'endpoints': {
        'analysis': True,
        'biosample': True,
        'genomicVariant': True,
        'individual': True,
        'run': True
    },
    'testMode': True,
    'database': 'mongo'
}
g_variants={
    'granularity': {
        'boolean': True,
        'count': True,
        'record': True
    },
    'singleEntryUrl': True,
    'endpoints': {
        'analysis': True,
        'biosample': True,
        'individual': True,
        'run': True
    },
    'testMode': True,
    'database': 'mongo'
}
individuals={
    'granularity': {
        'boolean': True,
        'count': True,
        'record': True
    },
    'singleEntryUrl': True,
    'endpoints': {
        'analysis': True,
        'biosample': True,
        'genomicVariant': True,
        'run': True
    },
    'testMode': True,
    'database': 'mongo'
}
runs={
    'granularity': {
        'boolean': True,
        'count': True,
        'record': True
    },
    'singleEntryUrl': True,
    'endpoints': {
        'analysis': True,
        'genomicVariant': True
    },
    'testMode': True,
    'database': 'mongo'
}
filtering_terms={
    'database': 'mongo'
}