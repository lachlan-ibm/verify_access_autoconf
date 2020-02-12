#!/bin/bash
import os
import sys
import logging
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
import requests

if __name__ == "__main__":
    import configure_aac as aac
    import configure_webseal as web
    import configure_fed as fed
    import constants as const
else:
    from . import configure_aac as aac
    from . import configure_webseal as web
    from . import configure_fed as fed
    from . import constants as const


_logger = logging.getLogger(__name__)

def accept_eula():
    payload = {"accepted": True}
    rsp = requests.put(const.MGMT_BASE_URL + "/setup_service_agreements/accepted", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Failed to accept EULA, status code:" + str(rsp.status_code)
    _logger.info("Accepted EULA")


def complete_setup():
    rsp = requests.put(const.MGMT_BASE_URL + "/setup_complete", 
            auth=const.CREDS, headers=const.HEADERS, verify=False)
    assert rsp.status_code == 200, "Did not complete setup"
    const.deploy_pending_changes()
    _logger.info("Completed setup")


def _update_routes(route):
    system = const.FACTORY.get_system_settings()
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

def _update_interface(iface):
    system = const.FACTORY.get_system_settings()
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

def update_network():
    config = const.CONFIG.appliance
    if config.network != None:
        if config.network.routes != None:
            for route in config.network.routes:
                _update_routes(route)
        if config.network.interfaces != None:
            for iface in config.network.interfaces:
                _update_interface(iface)
    const.deploy_pending_changes()


def _activateBaseAppliance():
    payload = {'code': const.CONFIG.appliance.activation.base}
    rsp = requests.post(const.MGMT_BASE_URL + "/isam/capabilities/v1", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the base license, statuc_code: {}\n{}".format(
            rsp.status_code, rsp.data)
    _logger.info("applied Base licence")

def _activateAdvancedAccessControl():
    payload = {'code': const.CONFIG.appliance.activation.aac}
    rsp = requests.post(const.MGMT_BASE_URL + "/isam/capabilities/v1", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the aac license, statuc_code: {}\n{}".format(
            rsp.status_code, rsp.data)
    _logger.info("applied AAC licence")

def _activateFederation():
    payload = {'code': const.CONFIG.appliance.activation.fed}
    rsp = requests.post(const.MGMT_BASE_URL + "/isam/capabilities/v1", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the fed license, statuc_code: {}/n{}".format(
            rsp.status_code, rsp.data)
    _logger.info("applied Federation licence")


def activate_appliance():
    system = const.FACTORY.get_system_settings()
    activations = system.licensing.get_activated_modules().json
    if not any(module.get('id', None) == 'wga' and module.get('enabled', "False") == "True" for module in activations):
        _activateBaseAppliance()
    if not any(module.get('id', None) == 'mga' and module.get('enabled', "False") == "True" for module in activations):
        _activateAdvancedAccessControl()
    if not any(module.get('id', None) == 'federation' and module.get('enabled', "False") == "True" for module in activations):
        _activateFederation()
    const.deploy_pending_changes()
    _logger.info("appliance activated")


def first_steps():
    accept_eula()
    complete_setup()
    update_network()
    activate_appliance()


def configure():
    web.configure()
    aac.configure()
    fed.configure()

if __name__ == "__main__":
    if const.CONFIG_BASE_DIR == None:
        _logger.error("Must set env varibale \"CONFIG_BASE_DIR\"." 
                " This should be the absolute path the configuration files required to set up ISVA")
    import json
    print(json.dumps(const.CONFIG, indent=4))
    first_steps()
    configure()
