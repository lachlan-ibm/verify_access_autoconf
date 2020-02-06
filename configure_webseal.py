#!/bin/python3

import logging
import json

from .constants import WEB, deploy_pending_changes

_logger = logging.getLogger(__name__)


def _update_stanza(proxy_id, config):
    for entry in config:
        rsp = WEB.reverse_proxy.update_configuration_stanza_entry(
                proxy_id, entry.stanza, entry.entry, entry.value)
        if rsp.success == True:
            _logger.info("Successfully updated stanza [{}] with [{}:{}]".format(
                    entry.stanza, entry.entry, entry.value))
        else:
            _logger.error("Failed to update stanza [{}] with [{}:{}]".format(
                    entry.stanza, entry.entry, entry.value))


def _configure_aac(proxy_id, aac_config):
    rsp = WEB.reverse_proxy.configure_aac(proxy_id, **aac_config)
    if rsp.success == True:
        _logger.info("Successfully ran Advanced Access Control configuration wizard on {} proxy instance".format(proxy_id))
    else:
        _logger.error("Failed to run AAC configuration wizard on {} proxy instance with config:\n{}".format(
            proxy_id, json.dumps(aac_config, indent=4)))


def _configure_mmfa(proxy_id, mmfa_config):
    rsp = WEB.reverse_proxy.configure_mmfa(proxy_id, **mmfa_config)
    if rsp.success == True:
        _logger.info("Successfully ran MMFA configuration wizard on {} proxy instance".format(proxy_id))
    else:
        _logger.error("Failed to run MMFA configuration wizard on {} proxy instance with config:\n{}".format(
            proxy_id, json.dumps(mmfa_config, indent=4)))


def _configure_federations(proxy_id, fed_config):
    rsp = WEB.reverse_proxy.configure_fed(proxy_id, **fed_config )
    if rsp.success == True:
        _logger.info("Successfully ran federation configuration utility with")
    else:
        _logger.error("Federation configuration wizard did not run successfully with config:\n{}".format(
            json.dumps(fed_config, indent=4)))


def _add_junction(proxy_id, junction):
    forceJunction = False
    jcts_response = WEB.reverse_proxy.list_junctions(proxy_id)
    if jcts_response != None and jcts_response.success = True:
        for jct in jcts.json:
            if jct["id"] == junction.name:
                junction['force'] = "yes"

    rsp = WEB.reverse_proxy.create_junction(proxy_id, **junction)
    
    if rsp.success == True:
        _logger.info("Successfully added junction to {} proxy".format(proxy_id))
    else:
        _logger.error("Failed to add junction to {} with config:\n{}".format(
            proxy_id, json.dumps(junction, indnet=4)))


def configure_wrp(runtime, proxy):
    rsp = WEB.reverse_proxy.create_instance(inst_name=proxy.name, 
                                      host=proxy.hostname, 
                                      admin_id=runtime.admin_user if runtime.admin_user else "sec_master", 
                                      admin_pwd=runtime.admin_.password,
                                      ssl_yn=proxy.ldap.ssl, 
                                      key_file=proxy.ldap.key_file, 
                                      cert_label=proxy.ldap.cert_file, 
                                      ssl_port=proxy.ldap.port,
                                      http_yn=proxy.http.enabled, 
                                      http_port=proxy.http.port, 
                                      https_yn=proxy.https.enabled, 
                                      https_port=proxy.https.port,
                                      nw_interface_yn="yes" if proxy.address else "no",
                                      ip_address=proxy.address, 
                                      listening_port=proxy.listening_port,
                                      domain=proxy.domain)
    if rsp.success == True:
        _logger.info("Successfully configured proxy {}".format(proxy.name))
    else:
        _logger.error("Configuration of proxy failed with config:\n{}".format(
            json.dumps(proxy, indent=4)))
        return

    if proxy.junctions != None:
        for jct in proxy.junctons:
            _add_junction(proxy.name, jct)

    if proxy.aac_configuration != None:
        _configure_aac(proxy.name, proxy.aac_configuration)

    if proxy.mmfa_configuration != None:
        _configure_mmfa(proxy.name, proxy.mmfa_configuration)

    if proxy.federation_configuration != None:
        _configure_federations(proxy.name, proxy.federation_configuration)

    if proxy.stanza_config != None:
        _update_stanza(proxy.name, proxy.stanza_config)


def configure_user(runtime, user):
    firstName = user.first_name if user.first_name else user.name
    lastName = user.last_name if user.last_name else user.name
    pdadminCommands = [
            "user create {} cn={},dc={} {} {} {}".format(user.name, user.name, user.domain, firstName, lastName, user.password),
            "user modify {} account-valid yes".format(user.name)
        ]
    rsp = WEB.policy_administration.execute(runtime.admin_user, runtime.admin_password, pdadminCommands)
    if rsp.success == True:
        _logger.info("Successfullt created user {}".format(user.name))
    else:
        _logger.error("Failed to create user {} with config:\n{}".format(user.name, json.dumps(user, indnet=4)))


def configure_runtime(runtime):
    rte_status = WEB.runtime_component.get_status()
    if rte_status.json['status'] == "Avaliable":
        rsp = WEB.runtime_component.unconfigure(ldap_dn=runtime.ldap_dn, ldap_pwd=runtime.ldap_dn, clean=runtime.clean_ldap, force=True)
        if rsp.success == True:
            _logger.info("Successfully unconfigured RTE")
        else:
            _logger.error("RTE cannot be unconfigured, will not override config")
            return

    config = {"ps_mode": runtime.ps_mode,
              "user_registry": "local" if runtime.ps_mode == "local" else "ldap",
              "ldap_dn": runtime.ldap_dn,
              "ldap_suffix": runtime.ldap_suffix,
              "clean_ldap": runtime.clean_ldap,
              "domain": runtime.domain,
              "admin_pwd": runtime.admin_password,
              "admin_cert_lifetime": runtime.admin_cert_lifetime
              "ssl_compliance": runtime.ssl_compliance
            }
    if runtime.ps_mode != None and runtime.ps_mode == "remote":
        config += {
                    "ldap_host": runtime.ldap.host,
                    "ldap_port": runtime.ldap.port,
                    "ldap_dn": runtime.ldap.dn,
                    "ldap_pwd": runtime.ldap.dn_password,
                    "ldap_ssl_db": runtime.ldap.ssl_keystore,
                    "ldap_ssl_label": runtime.ldap.ssl_cert
                }
    rsp = WEB.runtime_component.configure(**config)
    if rsp.success == True:
        _logger.info("Successfullt configured RTE")
    else:
        _logger.error("Failed to configure RTE with config:\n{}".format(json.dumps(runtime, indent=4)))


def configure():
    websealConfig = CONFIG.webseal
    if websealConfig == None:
        _logger.info("No webseal configuration found . . .  skipping")
        return

    if websealConfig.runtime != None:
        runtime = websealConfig.runtime
        configure_runtime(runtime)

        if websealConfig.reverse_proxy != None:
            for proxy in websealConfig.webseal.reverse_proxy:
                configure_wrp(runtime, proxy)

        if websealConfig.users != None:
            for user in websealConfig.users:
                configure_user(runtime, user)
        deploy_pending_changes()
    else:
        _logger.info("No runtime configuration detected, unable to set up any reverse proxy config")

if __name__ == "__main__":
        configure()
