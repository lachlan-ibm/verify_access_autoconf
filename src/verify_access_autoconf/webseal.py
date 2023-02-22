#!/bin/python3

import logging
import json

from .util.configure_util import deploy_pending_changes
from .util.data_util import Map, FILE_LOADER

_logger = logging.getLogger(__name__)

class WEB_Configurator(object):

    factory = None
    web = None
    config = Map()

    def __init__(self, config, factory):
        self.web = factory.get_web_settings()
        self.factory = factory
        self.config = config

    def __update_stanza(self, proxy_id, entry):
        rsp = self.web.reverse_proxy.update_configuration_stanza_entry(
                proxy_id, entry.stanza, entry.entry_id, entry.value)
        if rsp.success == True:
            _logger.info("Successfully updated stanza [{}] with [{}:{}]".format(
                    entry.stanza, entry.entry_id, entry.value))
        else:
            _logger.error("Failed to update stanza [{}] with [{}:{}]".format(
                    entry.stanza, entry.entry_id, entry.value))

    def __add_stanza(self, proxy_id, entry):
        rsp = None
        if entry.entry_id:
            rsp = self.web.reverse_proxy.add_configuration_stanza_entry(
                    proxy_id, entry.stanza, entry.entry_id, entry.value)
        elif entry.stanza:
            rsp = self.web.reverse_proxy.add_configuration_stanza(proxy_id, entry.stanza)
        else:
            _logger.error("Configuration invalid:\n{}".format(json.dumps(entry, indent=4)))
            return
        if rsp.success == True:
            _logger.info("Successfully created stanza entry")
        else:
            _logger.error("Failed to create stanza entry:\n{}\n{}".format(json.dumps(entry, indent=4), rsp.content))

    def __detele_stanza(self, proxy_id, entry):
        rsp = None
        if entry.entry_id:
            rsp = self.web.reverse_proxy.delete_configuration_stanza_entry(proxy_id, entry.stanza, entry.entry_id,
                    entry.value)
        elif entry.stanza:
            rsp = self.web.reverse_proxy.delete_configuration_stanza(proxy_id, entry.stana)
        else:
            _logger.error("Stanza configuration entry invalid:\n{}".format(json.dumps(entry, indent=4)))
            return
        if rsp.success == True:
            _logger.info("Successfully deleted stanza entry")
        else:
            _logger.error("Failed to delete stanza entry:\n{}\n{}".format(json.dumps(entry, indent=4), rsp.content))

    def _configure_stanza(self, proxy_id, config):
        for entry in config:
            if entry.operation == "delete":
                self.__delete_stanza(proxy_id, entry)
            elif entry.operation == "add":
                self.__add_stanza(proxy_id, entry)
            elif entry.operation == "update":
                self.__update_stanza(proxy_id, entry)
            else:
                _logger.error("Unknown operation {} in stanza entry: {}".format(
                    entry.operation, json.dumps(entry, indent=4)))

    def _configure_aac(self, proxy_id, aac_config):
        methodArgs = {
                "junction": aac_config.junction,
                "reuse_certs": aac_config.reuse_certs,
                "reuse_acls": aac_config.reuse_acls
            }
        if aac_config.runtime:
            methodArgs.update({
                                "runtime_hostname": aac_config.runtime.hostname,
                                "runtime_port": aac_config.runtime.port,
                                "runtime_username": aac_config.runtime.user,
                                "runtime_password": aac_config.runtime.password
                            })
        rsp = self.web.reverse_proxy.configure_aac(proxy_id, **methodArgs)
        if rsp.success == True:
            _logger.info("Successfully ran Advanced Access Control configuration wizard on {} proxy instance".format(proxy_id))
        else:
            _logger.error("Failed to run AAC configuration wizard on {} proxy instance with config:\n{}".format(
                proxy_id, json.dumps(aac_config, indent=4)))


    def _configure_mmfa(self, proxy_id, mmfa_config):
        methodArgs = {
                "reuse_acls": mmfa_config.reuse_acls,
                "reuse_pops": mmfa_config.reuse_pops,
                "reuse_certs": mmfa_config.reuse_certs,
                "channel": mmfa_config.channel
            }
        if mmfa_config.lmi:
            lmi = mmfa_config.lmi
            methodArgs.update({
                    "lmi_hostname": lmi.hostname,
                    "lmi_port": lmi.port,
                    "lmi_username": lmi.username,
                    "lmi_password": lmi.password
                })
        if mmfa_config.runtime:
            runtime = mmfa_config.runtime
            methodArgs.update({
                    "runtime_hostname": runtime.hostname,
                    "runtime_port": runtime.port,
                    "runtime_username": runtime.username,
                    "runtime_password": runtime.password
                })
        rsp = self.web.reverse_proxy.configure_mmfa(proxy_id, **methodArgs)
        if rsp.success == True:
            _logger.info("Successfully ran MMFA configuration wizard on {} proxy instance".format(proxy_id))
        else:
            _logger.error("Failed to run MMFA configuration wizard on {} proxy instance with config:\n{}".format(
                proxy_id, json.dumps(mmfa_config, indent=4)))


    def _configure_federations(self, proxy_id, fed_config):
        rsp = self.web.reverse_proxy.configure_fed(proxy_id, **fed_config )
        if rsp.success == True:
            _logger.info("Successfully ran federation configuration utility with")
        else:
            _logger.error("Federation configuration wizard did not run successfully with config:\n{}".format(
                json.dumps(fed_config, indent=4)))


    def _add_junction(self, proxy_id, junction):
        forceJunction = False
        junctions = self.web.reverse_proxy.list_junctions(proxy_id).json
        for jct in junctions:
            if jct["id"] == junction.junction_point:
                junction['force'] = "yes"

        rsp = self.web.reverse_proxy.create_junction(proxy_id, **junction)

        if rsp.success == True:
            _logger.info("Successfully added junction to {} proxy".format(proxy_id))
        else:
            _logger.error("Failed to add junction to {} with config:\n{}".format(
                proxy_id, json.dumps(junction, indnet=4)))


    '''
    .. note:: Configuration to connect to the user registry is read from the ``webseal.runtime`` entry.

    .. note:: Federations configured in ths step must already exist. If federations are beign created and configured
              for WebSEAL at the same time then the reverse proxy configuration should be added to the federation
              configuration dictionary.


    :var: reverse_proxy::

                        :var: name::
                        :var: host::
                        :var: nw_interface_yn::
                        :var: ip_address::
                        :var: listening_port::
                        :var: domain::
                        :var: ldap::
                                    :var: ssl::
                                    :var: key_file::
                                    :var: cert_file::
                                    :var: port::

                        :var: http::
                                    :var: enabled::
                                    :var: port::

                        :var: https::
                                    :var: enabled::
                                    :var port::

                        :var: junctions:: List of junctions to create. Each entry in the list should be a dictonary of
                                          properties to create a junction to a resource server. The complete list of
                                          properties that can be used to craete junctions can be found
                                          :ref:`here <pyisva:websettings#pyisva.core.web.reverseproxy.ReverseProxy.create_junction>`.

                        :var: aac_config::
                                                :var: junction::
                                                :var: reuse_certs::
                                                :var: reuse_acls::
                                                :var: runtime::
                                                                :var: hostname::
                                                                :var: port::
                                                                :var: username::
                                                                :var: password::

                        :var: mmfa_config::
                                            :var: channel::
                                            :var: reuse_acls::
                                            :var: reuse_pops::
                                            :var: reuse_certs::
                                            :var: lmi::
                                                        :var: hostname::
                                                        :var: port::
                                                        :var: username::
                                                        :var: password::

                                            :var: runtime::
                                                            :var: hostname::
                                                            :var: port::
                                                            :var: username::
                                                            :var: password::

                        :var: federation_configuration::
                                                        :var: name::
                                                        :var: reuse_certs::
                                                        :var: reuse_acls::
                                                        :var: runtime::
                                                                        :var: host::
                                                                        :var: port::
                                                                        :var: username::
                                                                        :var: password::

                        :var: stanza_configuration::
                                                    :var: operation::
                                                    :var: stanza::
                                                    :var: entry_id::
                                                    :var: value::

    Example::
              reverse_proxy:
              - name: "default"
                host: "hostname"
                listening_port: 7234
                domain: "Default"
                http:
                - enabled: "no"
                https:
                - enabled: "yes"
                  port: 443
                junctions:
                - name: "/app"
                  transparent_path: True
                  server:
                    host: "1.2.3.4"
                    port: 443
                  ssl:
                  - enabled: "yes"
                    key_file: "example.kdb",
                    cert_file: "server"
                aac_configuration_wizard:
                  hostname: "localhost"
                  port: 443
                  runtime:
                    user: "easuser"
                    password: "password"
                  junction: "/mga"
                  reuse_acls: True
                  reuse_certs: True
    '''
    def wrp(self, runtime, proxy):
        wrp_instances = self.web.reverse_proxy.list_instances().json
        if wrp_instances == None:
            wrp_instances = []
        for instance in wrp_instances:
            if instance['id'] == proxy.name:
                rsp = self.web.reverse_proxy.delete_instance(proxy.name,
                        runtime.admin_user if runtime.admin_user else "sec_master",
                        runtime.admin_password)
                if rsp.success != True:
                    _logger.error("WebSEAL Reverse proxy {} already exists with config: \n{}\nand cannot be removed".format(
                        proxy.name, proxy))
                    return
        methodArgs = {
                        "inst_name":proxy.name,
                        "host": proxy.host,
                        "admin_id": runtime.admin_user if runtime.admin_user else "sec_master",
                        "admin_pwd": runtime.admin_password,
                        "nw_interface_yn":  proxy.nw_interface_yn,
                        "ip_address": proxy.ip_address,
                        "listening_port": proxy.listening_port,
                        "domain": proxy.domain
                }
        if proxy.http != None:
            methodArgs.update({
                        "http_yn": proxy.http.enabled,
                        "http_port": proxy.http.port,
                        })
        if proxy.https != None:
            methodArgs.update({
                        "https_yn": proxy.https.enabled,
                        "https_port": proxy.https.port,
                        })
        if proxy.ldap != None:
            methodArgs.update({
                                "ssl_yn": proxy.ldap.ssl,
                                "key_file": proxy.ldap.key_file,
                                "cert_label": proxy.ldap.cert_file,
                                "ssl_port": proxy.ldap.port,
                        })
        rsp = self.web.reverse_proxy.create_instance(**methodArgs)
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
            self._configure_aac(proxy.name, proxy.aac_configuration)

        if proxy.mmfa_configuration != None:
            self._configure_mmfa(proxy.name, proxy.mmfa_configuration)

        if proxy.federation_configuration != None:
            self._configure_federations(proxy.name, proxy.federation_configuration)

        if proxy.stanza_configuration != None:
            self._configure_stanza(proxy.name, proxy.stanza_configuration)

        deploy_pending_changes(self.factory, self.config)
        if self.factory.is_docker() == False:
            rsp = self.web.reverse_proxy.restart_instance(proxy.name)
            if rsp.success == True:
                _logger.info("Successfully restart {} proxy instance after applying configuration".format(
                    proxy.name))
            else:
                _logger.error("Failed to restart {} proxy instance after applying configuration".format(
                    proxy.name))


    def _runtime_stanza(self, stanza_config):
        for entry in stanza_config:
            rsp = None
            if entry.operation == "add":
                entries = [ [entry.entry, entry.value] ] if entry.entry else None
                rsp = self.web.runtime_component.create_configuration_file_entry(resource=entry.resource,
                                                                                 stanza=entry.stanza, entries=entries)

            elif entry.operation == "update":
                if entry.entry == None or entry.value == None:
                    _logger.error("Update operation for {} is missing entry or value property, skipping".format(entry))
                    continue
                entries = [ [entry.entry, entry.value] ]
                rsp = self.web.runtime_component.update_configuration_file_entry(resource=entry.resource,
                                                                                stanza=entry.stanza, entries=entries)

            elif entry.operation == "delete":
                rsp = self.web.runtime_component.delete_configuration_file_entry(respource=entry.resource,
                                                                                 stanza=entry.stanza, entry=entry.entry,
                                                                                 value=entry.value)
            else:
                _logger.error("Unable to determine opreation for stanza file modification:\n{}\n. . . skipping".format(
                                                                                                                entry))
                continue
            if rsp.success == True:
                _logger.info("Successfully modified the {} stanza file".format(entry.stanza))
            else:
                _logger.error("Failed to modify stanza properties file with config:\n{}\n{}".format(
                                                                                json.dumps(entry, indent=4), rsp.data))


    '''
    :var: runtime:: Dictionary of properties to configure the Runtime Server and User Registry.

                :var: policy_server:: Mode of the Policy Server. "local" || "remote".
                :var: user_registry:: Mode of the User Registry. "local" || "remote".
                :var: clean_ldap:: Remove data from internal LDAP server. Only valid if ``policy_server`` or
                                   ``user_registry`` is "local".
                :var: isam_domain:: LDAP name to use for ``secAuthority`` attributes.
                :var: admin_password:: Secret to authenticate to LDAP server as the ``sec_master`` user.
                :var: admin_cert_lifetime::
                :var: ssl_complaince:: NIST Standard that SSL conforms to. eg "FIPS 140-2".
                :var: ldap:: Dictionary of connection properties for remote LDAP server. only valid if ``policy_server``
                            or ``user_registry`` is "remote".

                            :var: host:: Hostname or IP address of LDAP server.
                            :var: port:: Network prot that server is listening on.
                            :var: dn:: Distingueshed name to bind to server with. This name should have permission to
                                       create and modify schema in the Verify Access namespaces.
                            :var: dn_password:: Secret to authenticate as ``dn``.
                            :var: suffix (Optional):: Optional suffix to use.
                            :var: key_file::
                            :var: cert_file::

                :var: isam:: Properties use to connect to Verify Access policy server.

                            :var: host:: The name of the host that hosts the Security Verify Access policy server.
                            :var: port:: The port over which communication with the Security Verify Access policy server
                                         takes place.

                :var: stanza_configuration:: List of operations to perform on Stanza property files. Properties can
                                             be added, removed or modified.

                                            :var: operation:: "add", "remove", "update"
                                            :var: resource:: Name of configuration file to modify, eg ldap.conf, pd.conf, instance.conf
                                            :var: stanza:: Name of stanza to modify
                                            :var: entry:: Optional name of entry to modify
                                            :var: value:: Optional value to add, remove or update in a stanza file


    Example::
               runtime:
                 policy_server: "remote"
                 user_registry: "remote"
                 ldap:
                   host: "openldap"
                   port: 636
                   dn: "cn=root,secAuthority=Default"
                   dn_password: @secrets/isva-secrets:ldap-passwd
                   key_file: "lmi_trust_store"
                 clean_ldap: True
                 domain: "Default"
                 admin_password: @secrets/isva-secrets:secmaster-passwd
                 admin_cert_lifetime: 1460
                 ssl_compliance: "FIPS 140-2"
                 isam:
                   host: "isvaconfig"
                   port: 443
                 stanza_configuration:
                 - operation: "update"
                   resource: "ldap.conf"
                   stanza: "bind-credentials"
                   entry: "bind-dn"
                   value: "cn=root,secAuthority=Default"
                 - operation: "delete"
                   resource: "ldap.conf"
                   stanza: "server:MyFederatedDirectory"

    '''
    def runtime(self, runtime):
        rte_status = self.web.runtime_component.get_status()
        _logger.debug("ENTRY Runtime status: {}".format(rte_status.json))
        if rte_status.json['status'] == "Available":
            rsp = self.web.runtime_component.unconfigure(ldap_dn=runtime.ldap_dn, ldap_pwd=runtime.ldap_dn,
                    clean=runtime.clean_ldap, force=True)
            if rsp.success == True:
                _logger.info("Successfully unconfigured RTE")
            else:
                _logger.error("RTE cannot be unconfigured, will not override config")
                return

        config = {"ps_mode": runtime.policy_server,
                  "user_registry": runtime.user_registry,
                  "ldap_suffix": runtime.suffix,
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
                        "ldap_suffix": runtime.ldap.suffix,
                        "ldap_ssl_db": runtime.ldap.key_file,
                        "ldap_ssl_label": runtime.ldap.cert_file
                    })
        if runtime.isam:
            config.update({
                        "isam_host": runtime.isam.host,
                        "isam_port": runtime.isam.prt
                    })
        rsp = self.web.runtime_component.configure(**config)
        if rsp.success == True:
            _logger.info("Successfullt configured RTE")
        else:
            _logger.error("Failed to configure RTE with config:\n{}\n{}".format(
                json.dumps(runtime, indent=4), rsp.data))

        if runtime.stanza_configuration != None:
            self._runtime_stanza(runtime.stanza_configuration)

        _logger.debug("EXIT Runtime status: {}".format(self.web.runtime_component.get_status().json))
        return


    def _pdadmin_acl(self, runtime, acl):
        pdadminCommands = ["acl create {}".format(acl.name)]
        if acl.description:
            pdadminCommands += ["acl modify {} set desription {}".format(acl.name, acl.description)]
        if acl.attributes:
            for attribute in acl.attributes:
                pdadminCommands += ["acl modify {} set attribute {} {}".format(acl.name, attribute.name,
                    attribute.value)]
        if acl.users:
            for user in acl.users:
                pdadminCommands += ["acl modify {} set user {} {}".format(acl.name, user.name, user.permissions)]

        if acl.groups:
            for group in acl.groups:
                pdadminCommands += ["acl modify {} set group {} {}".format(acl.name, user.name, user.permissions)]

        if acl.any_other:
            pdadminCommands += ["acl modify {} set any-other {}".format(acl.name, acl.any_other)]

        if acl.unauthenticated:
            pdadmiNCommands += ["acl modify {} set unauthenticated {}".format(acl.name, acl.unauthenticated)]

        rsp = self.web.policy_administration.execute(runtime.admin_user, runtime.admin_password, pdadminCommands)
        if rsp.success == True:
            _logger.info("Successfullt created acl {}".format(acl.name))
        else:
            _logger.error("Failed to create acl {} with config:\n{}\n{}".format(acl.name, json.dumps(acl, indent=4),
                rsp.content))

    def _pdadmin_pop(self, runtime, pop):
        pdadminCommnads = ["pop create {}".format(pop.name)]
        if pop.description:
            pdadminCommands += ["pop modify {} set desription {}".format(pop.name, pop.description)]

        if pop.attributes:
            for attribute in pop.attributes:
                pdadminCommands += ["pop modify {} set attribute {} {}".format(pop.name, attrbute.name,
                    attribute.value)]

        if pop.tod_access:
            pdadminCommands += ["pop modify {} set tod-access {}".format(pop.name, pop.tod_access)]

        if pop.audit_level:
            pdadminCommands += ["pop modify {} set audit-level {}".format(pop.name, pop.audit_level)]

        if pop.ip_auth:
            if pop.ip_auth.any_other_network:
                pdadminCommands += ["pop modify {} set ipauth anyothernw {}".format(pop.name,
                    pop.ip_auth.any_other_network)]
            if pop.ip_auth.networks:
                for network in pop.ip_auth.networks:
                    pdadminCommands += ["pop modify {} set ipauth {} {}".format(pop.name, network.network,
                        network.netmask, network.auth_level)]

        rsp = self.web.policy_administration.execute(runtime.admin_user, runtime.admin_password, pdadminCommands)
        if rsp.success == True:
            _logger.info("Successfullt created pop {}".format(pop.name))
        else:
            _logger.error("Failed to create pop {} with config:\n{}\n{}".format(pop.name, json.dumps(pop, indent=4),
                rsp.content))

    def _pdadmin_proxy(self, runtime, proxy_config):
        pdadminCommands = []
        if proxy_config.acls:
            for acl in proxy_config.acls:
                for junction in acl.junctions:
                    pdadminCommands += ["acl attach /{}/{} {}".format(proxy_config.host, junction, acl.name)]

        if proxy_config.pops:
            for pop in proxy_config.pops:
                for junction in pop.junctions:
                    pdadminCommands += ["pop attach /{}/{} {}".format(proxy_config.host, junction, pop.name)]

        rsp = self.web.policy_administration.execute(runtime.admin_user, runtime.admin_password, pdadminCommands)
        if rsp.success == True:
            _logger.info("Successfullt attached acls/pops to {}".format(proxy_config.host))
        else:
            _logger.error("Failed to attach acls/pops to {} with config:\n{}\n{}".format(proxy_config.host,
                json.dumps(proxy_config, indent=4),
                rsp.content))

    def _pdadmin_user(self, runtime, user):
        firstName = user.first_name if user.first_name else user.name
        lastName = user.last_name if user.last_name else user.name
        pdadminCommands = [
                "user create {} {} {} {} {}".format(
                    user.name, user.dn, firstName, lastName, user.password),
                "user modify {} account-valid yes".format(user.name)
            ]
        rsp = self.web.policy_administration.execute(runtime.admin_user, runtime.admin_password, pdadminCommands)
        if rsp.success == True:
            _logger.info("Successfullt created user {}".format(user.name))
        else:
            _logger.error("Failed to create user {} with config:\n{}\n{}".format(user.name, json.dumps(user, indent=4),
                rsp.content))

    def _pdadmin_groups(self, runtime, group):
        pdadminCommands = ["group create {} {} {}".format(group.name, group.dn, group.description)]
        if group.users:
            for user in group.users:
                pdadminCommands += ["group modify {} add user {}".format(group.name, user)]
        rsp = self.web.policy_administration.execute(runtime.admin_user, runtime.admin_password, pdadminCommands)
        if rsp.success == True:
            _logger.info("Successfullt created group {}".format(group.name))
        else:
            _logger.error("Failed to create group {} with config:\n{}\n{}".format(group.name,
                json.dumps(group, indent=4), rsp.content))

    def _pdadmin(self, runtime, config):
        if config.acls != None:
            for acl in config.acls:
                self._pdadmin_acl(runtime, acl)

        if config.pops != None:
            for pop in config.pops:
                self._pdadmin_pop(runtime, pop)

        if config.groups != None:
            for group in config.groups:
                self._pdadmin_group(runtime, group)

        if config.users != None:
            for user in config.users:
                self._pdadmin_user(runtime, user)

        if config.reverse_proxies != None:
            for proxy in config.reverse_proxies:
                self._pdadmin_proxy(proxy)
        deploy_pending_changes(self.factory, self.config)


    '''
    :var: client_cert_mapping:: List of files to be uploaded as XLST rules for matching X509 certificates from an
                                incomming connection to the reverse proxy to an entity in the User Registry.

    Example::
               client_cert_mapping:
               - demo.mapping.xslt
               - cert_to_uid.xlst
    '''
    def client_cert_mapping(self, config):
        for cert_mapping in config:
            cert_mapping_file = FILE_LOADER.read_file(cert_mapping)
            if len(cert_mapping_file) != 1:
                _logger.error("Can only specify one cert mapping file")
                return
            rsp = self.web.client_cert_mapping.create(name=cert_mapping_file['name'], content=cert_mapping_file['content'])
            if rsp.success == True:
                _logger.info("Successfully configured certificate mapping")
            else:
                _logger.error("Failed to configure certificate mapping using {} config file".format(cert_mapping_file['name']))


    '''
    :var: junction_mapping:: List of files to be uploaded as junction mapping fules.

    Example::
            junction_mapping:
            - demo.jct.map
            - another.jct.map

    '''
    def junction_mapping(self, config):
        for junction_mapping in config:
            jct_mapping_file = FILE_LOADER.read_file(junction_mapping)
            if len(jct_mapping_file) != 1:
                _logger.error("Can only specify one jct mapping file")
                return
            rsp = self.web.jct_mapping.create(name=jct_mapping_file['name'], jmt_config_data=jct_mapping_file['content'])
            if rsp.success == True:
                _logger.info("Successfully configured junction mapping")
            else:
                _logger.error("Failed to configure junction mapping using {} config file".format(jct_mapping_file['name']))


    '''
    :var: url_mapping:: List of files to be uploaded as URL mapping rules.

    Examples::
              url-mapping:
              - dyn.url.conf
              - url.map.conf
    '''
    def url_mapping(self, config):
        for url_mapping in config:
            url_mapping_file = FILE_LOADER.read_file(url_mapping)
            if len(url_mapping_file) != 1:
                _logger.error("Can only specify one url mapping file")
                return
            rsp = self.web.url_mapping.create(name=url_mapping_file['name'], dynurl_config_data=url_mapping_file['content'])
            if rsp.success == True:
                _logger.info("Successfully configured URL mapping")
            else:
                _logger.error("Failed to configure URL mapping using {} config file".format(url_mapping_file['name']))


    '''
    :var: user_mapping:: List of XSLT files to be uploaded as user mapping rules.

    Example::
              user_mapping:
              - add_email.xslt
              - federated_identity_to_basic_user.xslt

    '''
    def user_mapping(self, config):
        for user_mapping in config:
            user_mapping_file = FILE_LOADER.read_file(user_mapping)
            if len(user_mapping_file) != 1:
                _logger.error("Can only specify one user mapping file")
                return
            rsp = self.web.user_mapping.create(name=user_mapping_file['name'], content=user_mapping_file['content'])
            if rsp.success == True:
                _logger.info("Successfully configured user mapping")
            else:
                _logger.error("Failed to configure user mapping using {} config file".format(user_mapping_file['name']))


    '''
    :var: fsso:: List of configuration files to be uloaded as Form Single Sign-On rules.

    Example::
            fsso:
            - liberty_jsp_fsso.conf
            - fsso.conf

    '''
    def form_single_sign_on(self, config):
        for fsso_config in config:
            fsso_config_file = FILE_LOADER.read_file(fsso_config)
            if len(user_mapping_file) != 1:
                _logger.error("Can only specify one FSSO configuration file")
                return
            rsp = self.web.fsso.create(name=fsso_config_file['name'], fsso_config_data=fsso_config_file['content'])
            if rsp.success == True:
                _logger.info("Successfully configured Federated Singe Sign On configuration")
            else:
                _logger.error("Failed to configure FSSO using {} config file".format(user_mapping_file['name']))


    '''
    :var: http_transforms:: List of files to be uploaded as HTTP Transformation Rules. These can be either LUA rules
                            using the ``.lua`` file extension or XSLT rules using the ``.xslt`` file extension.

    Example::
               http_transforms:
               - inject_header.xslt
               - eai.lua
    '''
    def http_transform(self, http_transform_rules):
        for http_transform_file_pointer in http_transform_rules:
            http_transform_files = FILE_LOADER.read_files(http_transform_file_pointer)
            for http_transform_file in http_transform_files:
                rsp = self.web.http_transform.create(name=http_transform_file['name'],
                        contents=http_transform_file['content'])
                if rsp.success == True:
                    _logger.info("Successfully created {} HTTP transform rule".format(http_transform_file['name']))
                else:
                    _logger.error("Failed to create {} HTTP transform rule".format(http_transform_file['name']))


    def __create_kerberos_property(self, _id, subsection, name, value):
        rsp = self.web.kerberos.create(_id=_id, name=name, value=value)
        if rsp.success == True:
            _logger.info("Successfully configured Kerberos property")
        else:
            _logger.error("Failed to configure Kerberos property:\nsubsection: {} name: {} value:{}\n{}".format(subsection,
                name, value, rsp.content))


    '''
    :var: kerberos:: Dictionary of Kerberos Domain and Realm configuration.

                    :var: libdefaults:: Dictionary of Kerberos properties to use as default properties.

                    :var: realms::

                                :var: name::
                                :var: properties::

                    :var: domain_realms::

                                :var: name::
                                :var: dns::

                    :var: keytabs:: List of files to import to Verify Access as Kerberos Keytab files.

                    :var: capaths::

    Example::

               kerberos:
                 libdefault:
                   default_realm: "test.com"
                 realms:
                 - name: "test.com"
                   properties:
                   - kdc: "test.com"
                 domain_realms:
                 - name: "demo.com"
                   dns: "test.com"
                 keytabs:
                 - admin.keytab
                 - user.keytab
    '''
    def kerberos(self, config):
        if config.libdefault != None:
            for kerbdef, value in config.libdefault: self.__create_kerberos_property('libdefault', kerbdef, kerbdef, value)
        if config.realms != None:
            for realm in config.realms:
                self.__create_kerberos_property("realms", realm.name, None, None)
                if realm.properties != None:
                    for k, v in realm.properties: self.__create_property("realms/" + realm.name, None, k, v)
        if config.domain_realms != None:
            for domain_realm in config.domain_realms: self.__create_kerberos_property("domain_realm", None,
                    domain_ream.name, domain_realm.dns)
        if config.capaths != None:
            for capath in config.capaths:
                self.__create_kerberos_property("capaths", capath.name, None, None)
                if capath.properties != None:
                    for prop, value  in capath.properties: elf.__create_kerberos_property("capaths/" + capath.name,
                            None, prop, value)
        if config.keytabs != None:
            for kf in config.keytabs:
                if not kf.startswith('/'):
                    kf = config_base_dir() + kf
                rsp = self.web.kerberos.import_keytab(kf)
                if rsp.success == True:
                    _logger.info("Successfully imported Kerberos Keytab file")
                else:
                    _logger.error("Failed to import Kerberos Keytab file:\n{}\n{}".format(json.dumps(prop, indent=4),
                        rsp.content))


    '''
    :var: password_strength:: List of XSLT file to be uploaded as password strength checks.

    Example::

               password_strength:
               - demo_rule.xlst

    '''
    def password_strength(self, password_strength_rules):
        pwd_config_file = FILE_LOADER.read_file(password_strength_rules)
        if len(pwd_mapping_file) != 1:
            _logger.error("Can only specify one password strength rule file")
            return
        rsp = self.web.password_strength.create(name=pwd_config_file['name'], content=pwd_config_file['content'])
        if rsp.success == True:
            _logger.info("Successfully configured password strength rules")
        else:
            _logger.error("Failed to configure password strength rules using {}".format(pwd_mapping_file['name']))


    '''
    :var: rsa_config:: Dictionary with two properties, each property is a configuration file to upload to Verify Access.

                    :var: server_config:: The server configuration file to upload.
                    :var: optional_server_config:: The server configuration options file to upload.

    Example::

               rsa_config:
                 server_config: server.conf
                 optional_server_config: optional_server.conf

    '''
    def rsa(self, rsa_config):
        rsp = self.web.rsa.create(name=rsa_config.server_config if rsa_config.server_config.startswith("/") else
              config_base_dir() + rsa_config.server_config)
        if rsp.success == True:
            _logger.info("Successfully configured RSA")
        else:
            _logger.error("Failed to configure RSA using {}".format(rsa_config.server_config))
        rsa_optional_config_file = None
        if rsa_config.optional_server_config != None:
            rsa_optional_config_file = rsa_config.optional_server_config


    def __apiac_resources(self, proxy_id, resources):
        for resource in resources:
            methodArgs = {
                    "server_hostname": resource.server_hostname,
                    "junction_point": resource.junction_point,
                    "junction_type": resource.junction_type,
                    "static_response_headers": resource.static_response_headers,
                    "description": resource.description,
                    "junction_hard_limit": resource.junction_hard_limit,
                    "junction_soft_limit": resource.junction_soft_limit,
                    "basic_auth_mode": resource.basic_auth_mode,
                    "tfim_sso": resource.tfim_sso,
                    "remote_http_header": resource.remote_http_header,
                    "stateful_junction": resource.stateful_junction,
                    "http2_junction": resource.http2_junction,
                    "sni_name": resource.sni_name,
                    "preserve_cookie": resource.preserve_cookie,
                    "cookie_include_path": resource.cookie_include_path,
                    "transparent_path_junction": resource.transparent_path_junction,
                    "mutual_auth": resource.mutual_auth,
                    "insert_ltpa_cookies": resource.insert_ltpa_cookies,
                    "insert_session_cookies": resource.insert_session_cookies,
                    "request_encoding": resource.request_encoding,
                    "enable_basic_auth": resource.enable_basic_auth,
                    "key_labelkey_label": resource.key_label,
                    "gso_resource_group": resource.gso_resource_group,
                    "junction_cookie_javascript_block": resource.junction_cookie_javascript_block,
                    "client_ip_http": resource.client_ip_http,
                    "version_two_cookies": resource.version_two_cookies,
                    "ltpa_keyfile": resource.ltpa_keyfile,
                    "authz_rules": resource.authz_rules,
                    "fsso_config_file": resource.fsso_config_file,
                    "username": resource.username,
                    "password": resource.password,
                    "server_uuid": resource.server_uuid,
                    "server_port": resource.server_port,
                    "virtual_hostname" : resource.virtual_hostname,
                    "server_dn": resource.server_dn,
                    "local_ip": resource.local_ip,
                    "query_contents": resource.query_contents,
                    "case_sensitive_url": resource.case_sensitive_url,
                    "windows_style_url": resource.windows_style_url,
                    "ltpa_keyfile_password": resource.ltpa_keyfile_password,
                    "https_port": resource.https_port,
                    "http_port": resource.http_port,
                    "proxy_hostname": resource.proxy_hostname,
                    "proxy_port": resource.proxy_port,
                    "sms_environment": resource.sms_environment,
                    "vhost_label": resource.vhost_label,
                    "force": resource.force,
                    "delegation_support": resource.delegation_support,
                    "scripting_support": resource.scripting_support
                }
            if resource.policy:
                policy = resurce.policy
                methodArgs.update({
                        "name": policy.name,
                        "type": policy.type
                    })
            if resource.authentication:
                methodArgs.update({"type": resource.authentication.type})
                if resource.autehntication.oauth_introspection:
                    oauth_introspection = resource.autehntication.oauth_introspection
                    methodArgs.update({
                            "oauth_introspection_transport": oauth_introspection.transport,
                            "oauth_introspection_endpoint": oauth_introspection.endpoint,
                            "oauth_introspection_proxy": oauth_introspection.proxy,
                            "oauth_introspection_auth_method": oauth_introspection.auth_method,
                            "oauth_introspection_client_id": oauth_introspection.client_id,
                            "oauth_introspection_client_secret": oauth_introspection.client_secret,
                            "oauth_introspection_client_id_hdr": oauth_introspection.client_id_hdr,
                            "oauth_introspection_token_type_hint": oauth_introspection.token_type_hint,
                            "oauth_introspection_mapped_id": oauth_introspection.mapped_id,
                            "oauth_introspection_external_user": oauth_introspection.external_user,
                            "oauth_introspection_response_attributes": oauth_introspection.response_attributes
                        })
                if resource.authentication.jwt:
                    jwt = resource.authentication.jwt
                    methodArgs.update({
                            "jwt_header_name": jwt.header_name,
                            "jwt_certificate": jwt.certificate,
                            "jwt_claims": jwt.claims
                        })
            rsp = self.web.api_access_control.resources.create_server(proxy_id, **methodArgs)
            if rsp.success == True:
                _logger.info("Successfully created {} API AC Resource server".format(resource.server_hostname))
            else:
                _logger.error("Failed to create {} API AC Resource serveer with config:\n{}\n{}".format(
                    resource.server_hostname, json.dumps(resource, indent=4), rsp.content))
                continue
            if resource.junctions:
                for junction in resource.junctions:
                    methodArgs = {
                            "server_type": junction.server_type,
                            "method": junction.method,
                            "path": junction.path,
                            "name": junction.name,
                            "static_response_headers": junction.static_response_headers,
                            "rate_limiting_policy": junction.rate_limiting_policy,
                            "url_aliases": junction.url_aliases
                        }
                    if junction.policy:
                        policy = junction.policy
                        methodArgs.update({
                                "policy_type": policy.type,
                                "policy_name": policy.name
                            })
                    if junction.documentation:
                        doc = junction.documentation
                        methodArgs.update({
                            "documentation_content_type": doc.content_type,
                            "documentation_file": doc.file
                        })
                    rsp = self.web.api_access_control.resources.create(proxy_id, resource.junction_point, **methodArgs)
                    if rsp.success == True:
                        _logger.info("Successfully created {} junctioned resource".format(junction.name))
                    else:
                        _logger.error("Failed to create {} junctioned resource with config;\n{}\n{}".format(
                            junction.name, json.dumps(junction, indent=4), rsp.content))

    def __apiac_cors(self, cors_policies):
        for cors in cors_policies:
            rsp = self.web.api_access_control.cors.create(name=cors.name, allowed_origins=cors.allowed_origins,
                    allow_credentials=cors.allow_credentials, exposed_headers=cors.exposed_headers,
                    handle_preflight=cors.handle_preflight, allowed_methods=cors.allowed_methods,
                    allowed_headers=cors.allowed_headers, max_age=cors.max_age)
            if rsp.success == True:
                _logger.info("Successfully created {} CORS policy".format(cors.name))
            else:
                _logger.error("Failed to create {} CORS policy using config:\n{}\n{}".format(cors.name,
                    json.dumps(cors, indent=4), rsp.content))

    def __apiac_document_root(self, proxy_id, doc_roots):
        for doc_root in doc_roots:
            files = FILE_LOADER.read_files(doc_root, include_directories=True)
            for _file in files:
                rsp = self.web.api_access_control.document_root.create(proxy_id, filename=_file['name'],
                        file_type=_file['type'], contents=_file.get('contents'))
                if rsp.success == True:
                    _logger.info("Successfully uploaded {} {}".format(_file['name'], _file['type']))
                else:
                    _logger.error("Failed to upload {} {}\n{}".format(_file["name"], _file["type"], rsp.content))

    def _api_access_control(self, runtime, apiac):
        rsp = self.web.api_access.control.utilities.store_credential(admin_id=runtime.admin_user,
                admin_pwd=runtime.admin_password, admin_doman=runtime.domain)
        if rsp.success == True:
            _logger.info("API Access Control successfully stored admin credential")
        else:
            _logger.error("API Access Control was unable to store admin credential")
            return
        if apiac.resources != None:
            __apiac_resources(apiac.resources)

        if apiac.cors != None:
            __apiac_cors(apiac.cors)

        if apiac.document_root != None:
            __apiac_document_root(apiac.document_root)


    def configure(self):

        if self.config.webseal == None:
            _logger.info("No WebSEAL configuration detected, skipping")
            return
        websealConfig = self.config.webseal
        if websealConfig.client_cert_mapping != None:
            self.client_cert_mapping(websealConfig.client_cert_mapping)

        if websealConfig.junction_mapping != None:
            self.junction_mapping(websealConfig.junction_mapping)

        if websealConfig.url_mapping != None:
            self.url_mapping(websealConfig.url_mapping)

        if websealConfig.user_mapping != None:
            self.user_mapping(websealConfig.user_mapping)

        if websealConfig.fsso != None:
            self.form_single_sign_on(websealConfig.fsso)

        if websealConfig.http_transform != None:
            self.http_transform(websealConfig.http_transform)

        if websealConfig.kerberos != None:
            self.kerberos(websealConfig.kerberos)

        if websealConfig.password_strength != None:
            self.password_strength(websealConfig.password_strength)

        if websealConfig.rsa_config != None:
            self.rsa(websealConfig.rsa_config)

        if websealConfig.runtime != None:
            self.runtime(websealConfig.runtime)
            if websealConfig.reverse_proxy != None:
                for proxy in websealConfig.reverse_proxy:
                    self.wrp(websealConfig.runtime, proxy)

            if websealConfig.api_access_control != None:
                self._api_access_control(websealConfig.api_access_control)

            if websealConfig.pdadmin != None:
                self._pdadmin(websealConfig.runtime, websealConfig.pdadmin)

        else:
            _logger.info("No runtime configuration detected, unable to set up any reverse proxy config or run pdadmin commands")


if __name__ == "__main__":
        configure()
