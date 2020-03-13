#!/bin/python
import logging
import requests
import json

from ..util.constants import FACTORY, CONFIG, CREDS, HEADERS, CONFIG_BASE_DIR, deploy_pending_changes

_logger = logging.getLogger(__name__)

class Appliance_Configurator(object):
    def _update_routes(self, route):
        system = FACTORY.get_system_settings()
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
        system = FACTORY.get_system_settings()
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
                            "vlan_id": iface.vlanId,
                            "bonding_mode": iface.bonding_mode,
                            "bonded_to": iface.bonded_to,
                        }
                if iface.ipv4 != None:
                    if iface.ipv4.dhcp != None:
                        methodArgs.update({
                                "ipv4_dhcp_enabled": iface.ipv4.dhcp.enabled,
                                "ipv4_dhcp_allow_management": iface.ipv4.dhcp.management,
                                "ipv4_dhcp_default_route": iface.ipv4.dhcp.provides_default_route,
                                "ipv4_dhcp_route_metric": iface.ipv4.dhcp.route_metric
                            })
                    if iface.ipv4.addresses != None and isinstance(iface.ipv4.addresses, list):
                        address = iface.ipv4.addresses[0]
                        methodArgs.update({
                                "ipv4_address": address.address,
                                "ipv4_mask_or_prefix": address.mask_or_prefix,
                                "ipv4_boradcast_address": address.broadcast_address,
                                "ipv4_allow_management": address.allow_management,
                                "ipv4_enabled": address.enabled
                            })
                rsp = system.interfaces.update_interface(oldIface['uuid'], **methodArgs)
                if rsp.success != True:
                    break
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
                            break

        if rsp != None and rsp.success == True:
            _logger.info("Successfuly set address for interface {}".format(iface.label))
        else:
            _logger.error("Failed to update address for interface {} with config:\n{}\n{}".format(
                iface.label, json.dumps(iface, indent=4), rsp.data))

    def update_network(self):
        config = CONFIG.appliance
        if config.network != None:
            if config.network.routes != None:
                for route in config.network.routes:
                    _update_routes(route)
            if config.network.interfaces != None:
                for iface in config.network.interfaces:
                    _update_interface(iface)
        deploy_pending_changes()


    def configure(self):
        update_network()

if __name__ == "__main__":
    configure()
