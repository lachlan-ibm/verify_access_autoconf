#!/bin/python
import logging
import requests
import json

from .util.constants import HEADERS
from .util.configure_util import creds, config_base_dir, deploy_pending_changes
from .util.data_util import Map

_logger = logging.getLogger(__name__)

class Appliance_Configurator(object):

    config = Map()
    appliance = None

    def __init__(self, appFctry, config):
        self.config = config
        self.appliance = appFctry


    def _update_routes(self, route):
        system = self.appliance.get_system_settings()
        interfaces = system.interfaces.list_interfaces().json["interfaces"]
        ifaceUuid = None
        for iface in interfaces:
            if iface.get('label', None) == route.interface:
                ifaceUuid = iface.get('uuid', '-1')
                break
        if ifaceUuid == None:
            _logger.error("Unable to find interface {} in : {}".format(
                route.interface, json.dumps(interfaces, indent=4)))
            return
        existingRoutes = system.static_routes.list_routes().json['staticRoutes']
        rsp = None
        for oldRoute in existingRoutes:
            if oldRoute['interfaceUUID'] == ifaceUuid:
                rsp = system.static_routes.update_route(oldRoute['uuid'], enabled=route.enabled,
                        address=route.address, mask_or_prefix=route.mask_or_prefix, gateway=route.gateway,
                        interface_uuid=ifaceUuid, metric=route.metric, comment=route.comment,
                        table=route.table)
                break
        if rsp == None:
            rsp = system.static_routes.create_route(enabled=route.enabled, address=route.address, mask_or_prefix=proxy.mask_or_prefix,
                    gateway=route.gateway, interface_uuid=ifaceUuid, metric=route.metric, comment=route.comment,
                    table=route.table)
        if rsp.success == True:
            _logger.info("Successfully set route info for {} interface".format(route.interface))
        else:
            _logger.error("Failed to set route info for {} interface:\n{}\n{}".format(
                route.info, json.dumps(route, indent=4), rsp.data))

    def _update_interface(self, iface):
        system = self.appliance.get_system_settings()
        interfaces = system.interfaces.list_interfaces().json["interfaces"]
        rsp = None
        if iface.ipv4 == None:
            _logger.error("Config tool only tested with IPv4 addresses, sorry")
            return
        for oldIface in interfaces:
            if iface.label == oldIface['label']:
                methodArgs = {
                            "name": iface.name,
                            "comment": iface.comment,
                            "enabled": iface.enabled,
                            "vlan_id": iface.vlan_id,
                            "bonding_mode": iface.bonding_mode,
                            "bonded_to": iface.bonded_to,
                        }
                if iface.ipv4 != None:
                    if iface.ipv4.dhcp != None:
                        methodArgs.update({
                                "ipv4_dhcp_enabled": iface.ipv4.dhcp.enabled,
                                "ipv4_dhcp_allow_management": iface.ipv4.dhcp.allow_mgmt,
                                "ipv4_dhcp_default_route": iface.ipv4.dhcp.provides_default_route,
                                "ipv4_dhcp_route_metric": iface.ipv4.dhcp.route_metric
                            })
                    if iface.ipv4.addresses != None and isinstance(iface.ipv4.addresses, list):
                        address = iface.ipv4.addresses[0]
                        methodArgs.update({
                                "ipv4_address": address.address,
                                "ipv4_mask_or_prefix": address.mask_or_prefix,
                                "ipv4_broadcast_address": address.broadcast_address,
                                "ipv4_allow_management": address.allow_mgmt,
                                "ipv4_enabled": address.enabled
                            })
                rsp = system.interfaces.update_interface(oldIface['uuid'], **methodArgs)
                if rsp.success != True:
                    break # Log error in outer if block
                if iface.ipv4.addresses != None:
                    for address in iface.ipv4.addresses[1:]:
                        methodArgs = {
                                "address": address.address,
                                "mask_or_prefix": address.mask_or_prefix,
                                "enabled": address.enabled,
                                "allow_management": address.allow_management
                            }
                        rsp = system.interfaces.create_address(iface.label, **methodArgs)
                        if rsp.success != True:
                            break # Log error in outer if block

        if rsp != None and rsp.success == True:
            _logger.info("Successfuly set address for interface {}".format(iface.label))
        else:
            _logger.error("Failed to update address for interface {} with config:\n{}\n{}".format(
                iface.label, json.dumps(iface, indent=4), rsp.data))


    '''
    :var: network:: Network configuration for attached interfaces.

                :var: routes:: List of network route settings.
                            :var: enabled:: Enable this interface
                            :var: interface::
                            :var: comment::
                            :var: address::
                            :var: gateway::
                            :var: mask_or_prefix::
                            :var: metric::
                            :var: table::

                :var: interfaces::
                                :var: name::
                                :var: comment::
                                :var: enabled::
                                :var: vlan_id::
                                :var: bonding_mode::
                                :var: bonded_to::
                                :var: ipv4::
                                            :var: dhcp:: Properties to enable DHCP on this interface.
                                                :var: enabled::
                                                :var: allow_mgmt::
                                                :var: default_route::
                                                :var: route_metric::
                                            :var: addresses:: List of 0 or more static addresses to assign to interface.
                                                            :var: address::
                                                            :var: mask_or_prefix::
                                                            :var: broadcast_address::
                                                            :var: allow_mgmt::
                                                            :var: enabled::


    Example::

            networking:
              routes:
              - enabled: true
                address: "default"
                gateway: "192.168.42.1"
                interface: "1.1"
                metric: 0
                table: "main"
                comment: "Example route"
              interfaces:
                ipv4:
                  dhcp:
                    enabled: false
                addresses:
                - address": "192.168.42.101"
                  mask_or_prefix: "255.255.255.0"
                  broadcast_address: "192.168.42.10"
                  allow_mgmt: true
                  enabled: true
                - address: "192.168.42.102"
                  mask_or_prefix: "/24"
                  broadcast_address: "192.168.42.10"
                  allow_mgmt: false
                  enabled: true

    '''
    def update_network(self, config):
        if config.network != None:
            if config.network.routes != None:
                for route in config.network.routes:
                    self._update_routes(route)
            if config.network.interfaces != None:
                for iface in config.network.interfaces:
                    self._update_interface(iface)
        deploy_pending_changes(self.factory, self.config)


    '''
    :var: enable_ntp:: Enable Network Time Protocol syncronization.
    :var: ntp_servers:: List of hostnames or IP addresses of NTP servers.
    :var: time_zone:: Timezone that appliance is operating in.
    :var: date_time:: The current date and time, in the format "YYYY-MM-DD HH:mm:ss".

    Examples::
            date_time:
              enable_ntp: true
              ntp_server: "time.ibm.com,192.168.0.1"
              time_zone: "Australia/Brisbane"
    '''
    def date_time(self, config):
        if config.date_time != None:
            rsp = self.appliance.get_system_settings().date_time.update(enable_ntp=config.date_time.enable_ntp,
                    ntp_servers=config.date_time.ntp_servers, time_zone=config.date_time.time_zone,
                    date_time=date_time.date_time)
            if rsp.success == True:
                _logger.info("Successfully updated Date/Time settings on appliance")
            else:
                _logger.error("Failed to update the Date/Time settings on the appliance with:\n{}\n{}".format(
                    json.dumps(config.date_time, indent=4), rsp.data))

    '''
    :var: config_db::

    :var: runtime_db::

    :var: cluster::

    Example::
               config_db:
                 address: "127.0.10.1"
                 port: 1234
                 username: "database_user"
                 password: "database_password"
                 ssl: True
                 ssl_keystore: "lmi_trust_store.kdb"
                 ssl_keyfile: "server.cer"
               runtime_db:
                 address: "postgresql"
                 port: 5432
                 type: "Postgresql"
                 user: "postgres"
                 password: !secret verify-access/isva-secrets:postgres-passwd
                 ssl: True
                 db_name: "isva"
               cluster:
                 sig_file: "cluster/signature_file"
                 primary_master: "isva.primary.master"
                 secondary_master: "isva.secondary.master"
                 nodes:
                 - "isva.node"
                 resitrcted_nodes:
                 - "isva.restricted.node"
    '''
    def cluster(self, config):
        if config.config_database != None:
            confDbExtraConfig = config.config_database.copy()
            methodArgs = {"embedded": False, "db_type": confDbExtraConfig.pop('type'), 'host': confDbExtraConfig.pop('host'),
                          'port': confDbExtraConfig.pop('port'), 'secure': confDbExtraConfig.pop('ssl'),
                          'user': confDbExtraConfig.pop('user'), 'passwd': confDbExtraConfig.pop('password'),
                          'db_name': confDbExtraConfig.pop('db_name'), 'extra_config': confDbExtraConfig
                }
            rsp = self.appliance.get_system_settings().cluster.set_config_db(**methodArgs)
            if rsp.success == True:
                _logger.info("Successfully set the configuration databaase")
            else:
                _logger.error("Failed to set the configuration database with:{}\n{}".format(
                    json.dumps(config.config_database, indent=4), rsp.content))
        if config.runtime_database != None:
            hvdbExtraConfig = config.runtime_database.copy()
            methodArgs = {'embedded': False, 'db_type': hvdbExtraConfig.pop('type'), 'host': hvdbExtraConfig.pop('host'),
                          'port': hvdbExtraConfig.po('port'), 'secure': hvdbExtraConfig.pop('ssl'),
                          'db_keystore': hvdbExtraConfig.pop('ssl_keystore'), 'user': hvdbExtraConfig.pop('user'),
                          'passwd': hvdbExtraConfig.pop('password'), 'db_name': hvdbExtraConfig.pop('db_name'),
                          'extra_config': hvdbExtraConfig
                }
            rsp = self.appliance.get_system_settings().cluster.set_runtime_db(**methodArgs)
            if rsp.success == True:
                _logger.info("Successfully set the runtime database")
            else:
                _logger.error("Failed to set the runtime database with: {}\n{}".format(json.dumps(
                    config.runtime_database, indent=4), rsp.content))
        if config.cluster != None:
            rsp = self.appliance.get_system_settings().cluster.update_cluster(**config.cluster)
            if rsp.success == True:
                _logger.info("Successfully set the cluster configuration")
            else:
                _logger.error("Failed to set the cluster configuration with:{}\n{}".format(
                    json.dumps(config.cluster, indent=4), rsp.content))


    def configure(self):
        self.update_network(self.config.appliance)
        self.date_time(self.config.appliance)
        self.cluster(self.config.appliance)

if __name__ == "__main__":
    configure()
