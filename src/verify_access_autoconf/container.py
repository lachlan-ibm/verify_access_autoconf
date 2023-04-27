#!/bin/python
"""
@copyright: IBM
"""
import logging
import requests
import json
import typing

from .util.constants import HEADERS
from .util.configure_util import deploy_pending_changes
from .util.data_util import Map

_logger = logging.getLogger(__name__)

class Docker_Configurator(object):

    config = Map()
    factory = None
    #There are errors deploying changes with some HVDB's so we choose to restart if the config is present not if successful
    needsRestart = False

    def __init__(self, config, factory):
        self.config = config
        self.factory = factory

    class Cluster_Configuration(typing.TypedDict):
        '''
        Example::


                  cluster:
                    runtime_database:
                      type: "postgresql"
                      host: "postgresql"
                      port: 5432
                      ssl: True
                      ssl_keystore: "rt_profile_keys"
                      username: "postgres"
                      password: "Passw0rd"
                      db_name: "isva"

        '''
        class Database(typing.TypedDict):
            type: str
            'Database type. "postgresql" | "db2" | "oracle".'
            host: str
            'Hostname or address of database.'
            port: str
            'Port database is listening on.'
            ssl: bool
            'Enable SSL encryption of connections.'
            ssl_keystore: typing.Optional[str]
            'SSL database to use to verify connections. Only valid if ``ssl == true``.'
            user: str
            'Username to authenticate to database as.'
            password: str
            'Password to authenticate as ``username``.'
            db_name: str
            'Name of the database instance to use.'
            extra_config: typing.Optional[dict]
            'Database type specific configuration.'

        runtime_database: typing.Optional[Database]
        'Configuration for the runtime (HVDB) database.'

    def configure_database(self, clusterConfig):
        system = self.factory.get_system_settings()
        if clusterConfig == None or clusterConfig.runtime_database == None:
            _logger.info("Cannot find HVDB configuration, in a docker environment this is probably bad")
            return
        self.needsRestart = True
        database = clusterConfig.runtime_database.copy()
        methodArgs = {'db_type': database.pop('type'), 'host': database.pop('host'), 'port': database.pop('port'),
                      'secure': database.pop('ssl'), 'db_key_store': database.pop('ssl_keystore', None), 
                      'user': database.pop('user'), 'passwd': database.pop('password'), 'db_name': database.pop('db_name'), 
                      'extra_config': database
            }
        rsp = system.cluster.set_runtime_db(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully configured HVDB")
        else:
            _logger.error("Failed to configure HVDB with config:\n{}\n{}".format(
                json.dumps(clusterConfig.runtime_database, indent=4), rsp.data))


    def configure(self):
        containerConfig = self.config.container
        if containerConfig == None:
            _logger.info("Unable to find container specific configuration")
            return
        self.configure_database(containerConfig.cluster)
        if self.needsRestart == True:
            deploy_pending_changes(self.factory, self.config)

if __name__ == "__main__":
    configure()
