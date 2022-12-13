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


    def configure_snapshot_publishing(self):
        system = self.factory.get_system_settings()
        if self.config.container.configuration_publishing == None:
            _logger.info("Cannot find configuration publishing user, will use admin user to publish configurations")
            return
        rsp = system.sysaccount.update_user(self.config.container.configuration_publishing.user, 
                password=self.config.container.configuration_publishing.password)
        if rsp.success == True:
            _logger.info("Successfully updated {} password".format(
                self.config.container.configuration_publishing.user))
        else:
            _logger.error("Failed to update password for {}\n{}".format(
                self.config.container.configuration_publishing.user, rsp.data))


    def configure_database(self):
        system = self.factory.get_system_settings()
        if self.config.container.cluster == None or self.config.container.cluster.runtime_database == None:
            _logger.info("Cannot find HVDB configuration, in a docker environment this is probably bad")
            return
        database = self.config.container.cluster.runtime_database
        rsp = system.cluster.seti_runtime_db(db_type=database.type, host=database.host, port=database.port,
                secure=database.ssl, user=database.username, passwd=database.password, db_name=database.db_name,
                db_key_store=database.ssl_keystore)
        if rsp.success == True:
            _logger.info("Successfully configured HVDB")
        else:
            _logger.error("Failed to configure HVDB with config:\n{}\n{}".format(
                json.dumps(database, indent=4), rsp.data))


    def configure(self):
        if self.config.container == None:
            _logger.info("Unable to find container specific configuration")
            return
        self.configure_snapshot_publishing()
        self.configure_database()
        deploy_pending_changes()

if __name__ == "__main__":
    configure()
