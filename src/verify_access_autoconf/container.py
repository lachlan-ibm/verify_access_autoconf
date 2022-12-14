#!/bin/python
import logging
import requests
import json

from .util.constants import HEADERS
from .util.configure_util import deploy_pending_changes
from .util.data_util import Map

_logger = logging.getLogger(__name__)

class Docker_Configurator(object):

    config = Map()
    factory = None

    def __init__(self, config, factory):
        self.config = config
        self.factory = factory


    def configure_snapshot_publishing(self, snapshotConfig):
        system = self.factory.get_system_settings()
        if snapshotConfig == None:
            _logger.info("Cannot find configuration publishing user, will use admin user to publish configurations")
            return
        rsp = system.sysaccount.update_user(snapshotConfig.user, password=snapshotConfig.password)
        if rsp.success == True:
            _logger.info("Successfully updated {} password".format(snapshotConfig.user))
        else:
            _logger.error("Failed to update password for {}\n{}".format(snapshotConfig.user, rsp.data))


    def configure_database(self, clusterConfig):
        system = self.factory.get_system_settings()
        if clusterConfig == None or clusterConfig.runtime_database == None:
            _logger.info("Cannot find HVDB configuration, in a docker environment this is probably bad")
            return
        database = clusterConfig.runtime_database.copy()
        methodArgs = {'db_type': database.pop('type'), 'host': database.pop('host'), 'port': database.pop('port'),
                      'secure': database.pop('ssl'), 'user': database.pop('user'), 'passwd': database.pop('password'), 
                      'db_name': database.pop('db_name'), 'db_key_store': database.pop('ssl_keystore'),
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
        self.configure_snapshot_publishing(containerConfig.configuration_publishing)
        self.configure_database(containerConfig.cluster)
        deploy_pending_changes(self.factory, self.config)

if __name__ == "__main__":
    configure()
