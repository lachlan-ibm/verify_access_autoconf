#!/bin/python
"""
@copyright: IBM
"""
import logging
import requests
import json
import typing

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
            _logger.info("Successfully set address for interface {}".format(iface.label))
        else:
            _logger.error("Failed to update address for interface {} with config:\n{}\n{}".format(
                iface.label, json.dumps(iface, indent=4), rsp.data))


    def _update_dns(self, dns_config):
        rsp = self.appliance.get_system_settings().dns.update(**dns_config)
        if rsp.success == True:
            _logger.info("Successfully set the DNS properties")
        else:
            _logger.error("Failed to set the DNS properties:\n{}\n{}".format(
                                                json.dumps(dns_config, indent=4) rsp.data))

    class Networking(typing.TypedDict):
        '''
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
        class Route(typing.TypedDict):
            enabled: bool
            'Enable this route.'
            interface: str
            'Interface this route is attached to.'
            comment: typing.Optional[str]
            'Optional comment to add to route.'
            address: str
            'Network address to use for route.'
            gateway: str
            'Network gateway to use for route.'
            maks_or_prefix: str
            'Network bitmask or prefix to use for route.'
            metric: int
            'Route metric.'
            table: int
            'Route table.'

        class Interface(typing.TypedDict):
            class IPv4(typing.TypedDict):
                class IPv4Address(typing.TypedDict):
                    address: str
                    'IPv4 address to assign to interface.'
                    mask_or_prefix: str
                    'IPv4 netmask or prefix to assign to address.'
                    broadcast_address: str
                    'IPv4 address to use for broadcasting.'
                    allow_mgmt: bool
                    'Use this address for the Local Management Interface.'
                    enabled: bool
                    'Enable this address.'

                class IPv4DHCP(typing.TypedDict):
                    enabled: bool
                    'Enable DHCP on this interface.'
                    allow_mgmt: bool
                    'Use a DHCP address for the Local Management Interface.'
                    default_route: bool
                    'Use DHCP to determine the default network route.'
                    route_metric: int
                    'Route metric.'

                dhcp: typing.Optional[IPv4DHCP]
                'DHCP configuration for an interface.'
                addresses: typing.Optional[typing.List[IPv4Address]]
                'Static IPv4 addresses assigned to an interface.'

            name: str
            'Name of interface.'
            comment: str
            'Comment to add to interface.'
            enabled: str
            'Enable this interface.'
            vlan_id: typing.Optional[str]
            'System assigned vlan ID.'
            ipv4: IPv4
            'IPv4 settings.'

        class DNS(typing.TypedDict):
            auto: bool
            'true if DNS should be auto configured via dhcp.'
            auto_from_interface: typing.Optional[str]
            'Name or ID of interface whose dhcp will defined the dns settings.'
            primary_server: typing.Optional[str]
            'Primary DNS Server address.'
            secondary_server: typing.Optional[str]
            'Secondary DNS Server address.'
            tertiary_server: typing.Optional[str]
            'Tertiary DNS Server address.'
            search_domains: typing.Optional[str]
            'Comma-separated list of DNS search domains.'


        routes: typing.Optional[typing.List[Route]]
        'Optional list of routes to add to an interface.'

        interfaces: typing.List[Interface]
        'List of properties for attached interfaces.'

        dns: typing.Optional[DNS]
        'Domain Name Server settings for appliance'

    def update_network(self, config):
        if config.network != None:
            if config.network.routes != None:
                for route in config.network.routes:
                    self._update_routes(route)
            if config.network.interfaces != None:
                for iface in config.network.interfaces:
                    self._update_interface(iface)
            if config.dns != None:
                self._update_dns(config.dns)
        deploy_pending_changes(self.factory, self.config)


    class Date_Time(typing.TypedDict):
        '''
        Example::

                    date_time:
                      enable_ntp: true
                      ntp_servers: "time.ibm.com,192.168.0.1"
                      time_zone: "Australia/Brisbane"

        '''
        enable_ntp: bool
        'Enable Network Time Protocol synchronization.'
        ntp_servers: typing.Optional[typing.List[str]]
        'List of hostnames or addresses to use as NTP servers.'
        time_zone: str
        'The id of the timezone the appliance is operating in.'
        date_time: typing.Optional[str]
        'The current date and time, in the format "YYYY-MM-DD HH:mm:ss"'

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


    class Cluster_Configuration(typing.TypedDict):
        '''
        Example::

                 cluster:
                   config_db:
                     address: "127.0.10.1"
                     port: 1234
                     username: "database_user"
                     password: "database_password"
                     ssl: True
                     ssl_keystore: "lmi_trust_store.kdb"
                     db_name: "isva_config"
                   runtime_db:
                     address: "postgresql"
                     port: 5432
                     type: "Postgresql"
                     user: "postgres"
                     password: !secret verify-access/isva-secrets:postgres-passwd
                     ssl: False
                     db_name: "isva_hvdb"
                   cluster:
                     sig_file: "cluster/signature_file"
                     primary_master: "isva.primary.master"
                     secondary_master: "isva.secondary.master"
                     nodes:
                     - "isva.node"
                     restricted_nodes:
                     - "isva.restricted.node"

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

        class Cluster(typing.TypedDict):
            sig_file: str
            'Signature file generated by the primary master; used to add nodes to the cluster.'
            primary_master: str
            'Verify Access appliance designated as the primary master node.'
            secondary_master: typing.Optional[str]
            'Verify Access appliance designated as the secondary master node.'
            nodes: typing.Optional[typing.List[str]]
            'Verify Access appliance designated as nodes.'
            restricted_nodes: typing.Optional[typing.List[str]]
            'Verify Access appliance designated as the restricted nodes.'

        config_database: typing.Optional[Database]
        'Configuration for the config database.'
        runtime_database: typing.Optional[Database]
        'Configuration for the runtime (HVDB) database.'
        cluster: typing.Optional[Cluster]
        'Configuration for Verify Access High Availability cluster nodes.'

    def cluster(self, config):
        if config.config_database != None:
            confDbExtraConfig = config.config_database.copy()
            methodArgs = {"embedded": False, "db_type": confDbExtraConfig.pop('type'), 'host': confDbExtraConfig.pop('host'),
                          'port': confDbExtraConfig.pop('port'), 'secure': confDbExtraConfig.pop('ssl'), 
                          'db_keystore': confDbExtraConfig.pop('ssl_keystore'), 'user': confDbExtraConfig.pop('user'), 
                          'passwd': confDbExtraConfig.pop('password'), 'db_name': confDbExtraConfig.pop('db_name'), 
                          'extra_config': confDbExtraConfig
                }
            rsp = self.appliance.get_system_settings().cluster.set_config_db(**methodArgs)
            if rsp.success == True:
                _logger.info("Successfully set the configuration database")
            else:
                _logger.error("Failed to set the configuration database with:{}\n{}".format(
                    json.dumps(config.config_database, indent=4), rsp.data))
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
                    config.runtime_database, indent=4), rsp.data))
        if config.cluster != None:
            rsp = self.appliance.get_system_settings().cluster.update_cluster(**config.cluster)
            if rsp.success == True:
                _logger.info("Successfully set the cluster configuration")
            else:
                _logger.error("Failed to set the cluster configuration with:{}\n{}".format(
                    json.dumps(config.cluster, indent=4), rsp.data))


    def configure(self):
        self.update_network(self.config.appliance)
        self.date_time(self.config.appliance)
        self.cluster(self.config.appliance)

if __name__ == "__main__":
    configure()
