#!/bin/python3

import logging
import json

from ..util.constants import CONFIG, WEB, deploy_pending_changes

_logger = logging.getLogger(__name__)

class WEB_Configurator(object):

    def _update_stanza(self, proxy_id, config):
        for entry in config:
            if entry.operation == "delete":
                #TODO
            elif entry.operation == "add":
                #TODO
            elif entry.operation == "update":
                rsp = WEB.reverse_proxy.update_configuration_stanza_entry(
                        proxy_id, entry.stanza, entry.key, entry.value)
                if rsp.success == True:
                    _logger.info("Successfully updated stanza [{}] with [{}:{}]".format(
                            entry.stanza, entry.key, entry.value))
                else:
                    _logger.error("Failed to update stanza [{}] with [{}:{}]".format(
                            entry.stanza, entry.key, entry.value))
            else:
                _logger.error("Unknown operation {} in stanza entry: {}".format(
                    entry.operation, json.dumps(entry, indent=4)))

    def _configure_aac(self, proxy_id, aac_config):
        methodArgs = {
                "runtime_hostname": aac_config.hostname,
                "runtime_port": aac_config.port,
                "junction": aac_config.junction,
                "runtime_username": aac_config.user,
                "runtime_password": aac_config.password,
                "reuse_certs": aac_config.reuse_certs,
                "reuse_acls": aac_config.reuse_acls
            }
        rsp = WEB.reverse_proxy.configure_aac(proxy_id, **methodArgs)
        if rsp.success == True:
            _logger.info("Successfully ran Advanced Access Control configuration wizard on {} proxy instance".format(proxy_id))
        else:
            _logger.error("Failed to run AAC configuration wizard on {} proxy instance with config:\n{}".format(
                proxy_id, json.dumps(aac_config, indent=4)))


    def _configure_mmfa(self, proxy_id, mmfa_config):
        rsp = WEB.reverse_proxy.configure_mmfa(proxy_id, **mmfa_config)
        if rsp.success == True:
            _logger.info("Successfully ran MMFA configuration wizard on {} proxy instance".format(proxy_id))
        else:
            _logger.error("Failed to run MMFA configuration wizard on {} proxy instance with config:\n{}".format(
                proxy_id, json.dumps(mmfa_config, indent=4)))


    def _configure_federations(self, proxy_id, fed_config):
        rsp = WEB.reverse_proxy.configure_fed(proxy_id, **fed_config )
        if rsp.success == True:
            _logger.info("Successfully ran federation configuration utility with")
        else:
            _logger.error("Federation configuration wizard did not run successfully with config:\n{}".format(
                json.dumps(fed_config, indent=4)))


    def _add_junction(self, proxy_id, junction):
        forceJunction = False
        junctions = WEB.reverse_proxy.list_junctions(proxy_id).json
        for jct in junctions:
            if jct["id"] == junction.junction_point:
                junction['force'] = "yes"

        rsp = WEB.reverse_proxy.create_junction(proxy_id, **junction)
        
        if rsp.success == True:
            _logger.info("Successfully added junction to {} proxy".format(proxy_id))
        else:
            _logger.error("Failed to add junction to {} with config:\n{}".format(
                proxy_id, json.dumps(junction, indnet=4)))


    def _wrp(self, runtime, proxy):
        wrp_instances = WEB.reverse_proxy.list_instances().json
        for instance in wrp_instances:
            if instance['id'] == proxy.name:
                rsp = WEB.reverse_proxy.delete_instance(proxy.name, 
                        runtime.admin_user if runtime.admin_user else "sec_master",
                        runtime.admin_password)
                if rsp.success != True:
                    _logger.error("WebSEAL Reverse proxy {} already exists with config: \n{}\nand cannot be removed".format(
                        proxy.name, proxy))
                    return
        host = proxy.hostname
        if not host:
            if CONFIG.docker and CONFIG.docker.containers and CONFIG.docker.containers.configuration:
                host = CONFIG.docker.containers.configuration[0]
        methodArgs = {
                        "inst_name":proxy.name, 
                        "host": host, 
                        "admin_id": runtime.admin_user if runtime.admin_user else "sec_master", 
                        "admin_pwd": runtime.admin_password,
                        "http_yn": proxy.http.enabled, 
                        "http_port": proxy.http.port, 
                        "https_yn": proxy.https.enabled, 
                        "https_port": proxy.https.port,
                        "nw_interface_yn":  proxy.nw_interface_yn,
                        "ip_address": proxy.ip_address, 
                        "listening_port": proxy.listening_port,
                        "domain": proxy.domain
                }
        if proxy.ldap != None:
            methodArgs.update({
                                "ssl_yn": proxy.ldap.ssl, 
                                "key_file": proxy.ldap.key_file, 
                                "cert_label": proxy.ldap.cert_file, 
                                "ssl_port": proxy.ldap.port,
                        })
        rsp = WEB.reverse_proxy.create_instance(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully configured proxy {}".format(proxy.name))
        else:
            _logger.error("Configuration of {} proxy failed with config:\n{}\n{}".format(
                proxy.name, json.dumps(proxy, indent=4), rsp.data))
            return

        if proxy.junctions != None:
            for jct in proxy.junctions:
                _add_junction(proxy.name, jct)

        if proxy.aac_configuration != None:
            _configure_aac(proxy.name, proxy.aac_configuration)

        if proxy.mmfa_configuration != None:
            _configure_mmfa(proxy.name, proxy.mmfa_configuration)

        if proxy.federation_configuration != None:
            _configure_federations(proxy.name, proxy.federation_configuration)

        if proxy.stanza_configuration != None:
            _update_stanza(proxy.name, proxy.stanza_configuration)

        deploy_pending_changes()
        rsp = WEB.reverse_proxy.restart_instance(proxy.name)
        if rsp.success == True:
            _logger.info("Successfully restart {} proxy instance after applying configuration".format(
                proxy.name))
        else:
            _logger.error("Failed to restart {} proxy instance after applying configuration".format(
                proxy.name))


    def _runtime(self, runtime):
        rte_status = WEB.runtime_component.get_status()
        if rte_status.json['status'] == "Available":
            rsp = WEB.runtime_component.unconfigure(ldap_dn=runtime.ldap_dn, ldap_pwd=runtime.ldap_dn, clean=runtime.clean_ldap, force=True)
            if rsp.success == True:
                _logger.info("Successfully unconfigured RTE")
            else:
                _logger.error("RTE cannot be unconfigured, will not override config")
                return

        config = {"ps_mode": runtime.policy_server,
                  "user_registry": runtime.user_registry,
                  "ldap_dn": runtime.ldap_dn,
                  "ldap_suffix": runtime.ldap_suffix,
                  "clean_ldap": runtime.clean_ldap,
                  "isam_domain": runtime.domain,
                  "admin_password": runtime.admin_password,
                  "admin_cert_lifetime": runtime.admin_cert_lifetime,
                  "ssl_compliance": runtime.ssl_compliance
                }
        if runtime.ldap:
            config.update({
                        "ldap_host": runtime.ldap.host,
                        "ldap_port": runtime.ldap.port,
                        "ldap_dn": runtime.ldap.dn,
                        "ldap_password": runtime.ldap.dn_password,
                    })
            if runtime.ldap.key_file:
                config.update({
                        "ldap_ssl_db": runtime.ldap.key_file
                    })
            if runtime.ldap.cert_file:
                config.update({
                        "ldap_ssl_label": runtime.ldap.cert_file
                    })
        rsp = WEB.runtime_component.configure(**config)
        if rsp.success == True:
            _logger.info("Successfullt configured RTE")
        else:
            _logger.error("Failed to configure RTE with config:\n{}\n{}".format(
                json.dumps(runtime, indent=4), rsp.data))
        return rsp.success


    def _pdadmin_acl(self, runtime, acl):
        #TODO

    def _pdadmin_pop(self, runtime, pop):
        #TODO

    def _pdadmin_proxy(self, runtime, proxy_config):
        #TODO

    def _pdadmin_user(self, runtime, user):
        firstName = user.first_name if user.first_name else user.name
        lastName = user.last_name if user.last_name else user.name
        dc = ""
        if isinstance(user.dc, list):
            for i, e in enumerate(user.dc):
                dc += "dc=" + e
                if i != len(user.dc) - 1:
                    dc += ","
        else:
            dc = "dc=" + user.dc
        print(dc)
        pdadminCommands = [
                "user create {} cn={},{} {} {} {}".format(
                    user.name, user.cn, dc, firstName, lastName, user.password),
                "user modify {} account-valid yes".format(user.name)
            ]
        rsp = WEB.policy_administration.execute(runtime.admin_user, runtime.admin_password, pdadminCommands)
        if rsp.success == True:
            _logger.info("Successfullt created user {}".format(user.name))
        else:
            _logger.error("Failed to create user {} with config:\n{}".format(user.name, json.dumps(user, indent=4)))

    def _pdadmin_groups(self, runtime, group):
        #TODO

    def _pdadmin(self, runtime, config):
        if config.acls != None:
            for acl in config.acls:
                _pdadmin_acl(runtime, acl)

        if config.pops != None:
            for pop in config.pops:
                _pdadmin_pop(runtime, pop)

        if config.groups != None:
            for group in config.groups:
                _pdadmin_group(runtime, group)

        if config.users != None:
            for user in config.users:
                _pdadmin_user(runtime, user)

        if config.reverse_proxies != None:
            for proxy in config.reverse_proxies:
                _pdadmin_proxy(proxy)
        deploy_pending_changes()


    def _client_cert_mapping(self, cert_mapping):
        #TODO

    def _junction_mapping(self, junction_mapping):
        #TODO

    def _url_mapping(self, url_mapping):
        #TODO

    def _user_mapping(self, user_mapping):
        #TODO

    def _federated_sso(self, fsso_config):
        #TODO

    def _http_transform(self, http_transform_rules):
        #TODO

    def _kerberos(self, kerberos_config):
        #TODO

    def _password_strengt(self, password_strength_rules):
        #TODO

    def _rsa(self, rsa_config):
        #TODO

    def __apiac_resources(self, resources):
        #TODO

    def __apiac_utilities(self, utilities):
        #TODO

    def __apiac_cors(self, cors):
        #TODO

    def __apiac_document_root(self, doc_root):
        #TODO

    def _api_access_control(self, apiac):
        if apiac.resources != None:
            __apiac_resources(apiac.resources)
        
        if apiac.utilities != None:
            __apiac_utilities(apiac.utilities)

        if apiac.cors != None:
            __apiac_cors(apiac.cors)

        if apiac.document_root != None:
            __apiac_document_root(apiac.document_root)


    def configure(self):
        websealConfig = CONFIG.webseal
        if websealConfig == None:
            _logger.info("No WebSEAL configuration detected, skipping")
            return
        
        if websealConfig.client_cert_mapping != None:
            _client_cert_mapping(websealConfig.client_cert_mapping)

        if websealConfig.junction_mapping != None:
            _junction_mapping(websealConfig.junction_mapping)

        if websealConfig.url_mapping != None:
            _url_mapping(websealConfig.url_mapping)

        if websealConfig.user_mapping != None:
            _user_mapping(websealConfig.user_mapping)

        if websealConfig.fsso != None:
            _federated_sso(websealConfig.fsso)

        if websealConfig.http_transform != None:
            _http_transform(websealConfig.http_transform)

        if websealConfig.kerberos != None:
            _kerberos(websealCOnfig.kerberos)

        if websealConfig.password_strength != None:
            _password_strength(websealConfig.password_strength)

        if websealConfig.rsa_config != None:
            _rsa(websealConfig.rsa_config)

        if websealConfig.runtime != None:
            _runtime(runtime)
            if websealConfig.reverse_proxy != None:
                for proxy in websealConfig.reverse_proxy:
                    _wrp(runtime, proxy)
            
            if websealConfig.pdadmin != None:
                _pdadmin(runtime, websealConfig.pdadmin)
        else:
            _logger.info("No runtime configuration detected, unable to set up any reverse proxy config or run pdadmin commands")

        if websealConfig.api_access_control != None:
            _api_access_control(websealConfig.api_access_control)


if __name__ == "__main__":
        configure()
