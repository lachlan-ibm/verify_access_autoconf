#!/bin/python
import logging
import requests
import json

from  .util.constants import FACTORY, CONFIG, CREDS, HEADERS, update_container_names, deploy_pending_changes

_logger = logging.getLogger(__name__)

class Docker_Configurator(object):
    def configure_configuration_publishing(self):
        system = FACTORY.get_system_settings()
        if CONFIG.docker.configuration_publishing == None:
            _logger.info("Cannot find configuration publishing user, will use admin user to publish configurations")
            return
        rsp = system.sysaccount.update_user(CONFIG.docker.configuration_publishing.user, 
                password=CONFIG.docker.configuration_publishing.password)
        if rsp.success == True:
            _logger.info("Successfully updated {} password".format(
                CONFIG.docker.configuration_publishing.user))
        else:
            _logger.error("Failed to update password for {}\n{}".format(
                CONFIG.docker.configuration_publishing.user, rsp.data))


    def configure_database(self):
        system = FACTORY.get_system_settings()
        if CONFIG.docker.database == None:
            _logger.info("Cannot find HVDB configuration, in a docker environment this is probably bad")
            return
        database = CONFIG.docker.database
        rsp = system.runtime_db.set_db(db_type=database.type, host=database.host, port=database.port,
                secure=database.ssl, user=database.username, passwd=database.password, db_name=database.db_name)
        if rsp.success == True:
            _logger.info("Successfully configured HVDB")
        else:
            _logger.error("Failed to configure HVDB with config:\n{}\n{}".format(
                json.dumps(database, indent=4), rsp.data))


    def configure(self):
        update_container_names()
        _logger.info(json.dumps(CONFIG, indent=4))
        configure_configuration_publishing()
        configure_database()
        deploy_pending_changes()

if __name__ == "__main__":
    configure()
