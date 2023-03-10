#!/bin/python3

import logging
import json
import typing

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

    class Reverse_Proxy(typing.TypedDict):
        '''
        .. note:: Configuration to connect to the user registry is read from the ``webseal.runtime`` entry.

        .. note:: Federations configured in ths step must already exist. If federations are beign created and configured
                  for WebSEAL at the same time then the reverse proxy configuration should be added to the federation
                  configuration dictionary.

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

        class AAC_Configuration(typing.TypedDict):
            class Liberty_Server(typing.TypedDict):
                hostname: str
                'Hostname or address of server.'
                port: int
                'Port server is listening on.'
                username: str
                'Username to use for basic authentication.'
                password: str
                'Passowrd to use for basic authentication.'

            junction: str
            'Junction to create.'
            runtime: Liberty_Server
            'Liberty runtime server properties.'
            reuse_acls: bool
            'Re-use existing Policy Server ACL\'s'
            reuse_certs: bool
            'Re-use existing certificates in the SSL database.'

        class MMFA_Configuration(typing.TypedDict):
            class Liberty_Server(typing.TypedDict):
                hostname: str
                'Hostname or address of server.'
                port: int
                'Port server is listening on.'
                username: str
                'Username to use for basic authentication.'
                password: str
                'Passowrd to use for basic authentication.'

            channel: str
            'MMFA channel to configure. "mobile" | "browser" | "both".'
            runtime: Liberty_Server
            'Liberty runtime server properties.'
            lmi: Liberty_Server
            'Liberty LMI server properties.'
            reuse_acls: bool
            'Re-use existing Policy Server ACL\'s'
            reuse_certs: bool
            'Re-use existing certificates in the SSL database.'
            reuse_pops: bool
            'Re-use existing Policy Server POP\'s'

        class Federation_Configuration(typing.TypedDict):
            class Liberty_Server(typing.TypedDict):
                hostname: str
                'Hostname or address of server.'
                port: int
                'Port server is listening on.'
                username: str
                'Username to use for basic authentication.'
                password: str
                'Passowrd to use for basic authentication.'

            name: str
            'Name of the Federation.'
            runtime: Liberty_Server
            'Liberty runtime server properties.'
            reuse_acls: bool
            'Re-use existing Policy Server ACL\'s'
            reuse_certs: bool
            'Re-use existing certificates in the SSL database.'

        class Stanza_Configuration(typing.TypedDict):
            operation:str
            'Operation to perform on configuration file. "add" | "delete" | "update".'
            stanza: str
            'Name of stanza to modify.'
            entry_id: typing.Optional[str]
            'Optional entry name to modify.'
            value: typing.Optional[str]
            'Optional entry value to modify.'

        class Junction(typing.TypedDict):
            junction_type: str
            'Type of junction.'
            junction_point: str
            'Name of the location in the Reverse Proxy namespace where the root of the back-end application server namespace is mounted.'
            description: typing.Optional[str]
            'An optional description for this junction.'
            server_hostname: str
            'The DNS host name or IP address of the target back-end server.'
            server_port: str
            'TCP port of the back-end third-party server.'
            basic_auth_mode: str
            'Defines how the Reverse Proxy server passes client identity information in HTTP basic authentication (BA) headers to the back-end server.'
            tfim_sso: bool
            'Enables IBM Security Federated Identity Manager single sign-on (SSO) for the junction. "yes" | "no"'
            stateful_junction: str
            'Specifies whether the junction supports stateful applications. "yes" | "no".'
            preserve_cookie: str
            'Specifies whether modifications of the names of non-domain cookies are to be made.'
            cookie_include_path: str
            'Specifies whether script generated server-relative URLs are included in cookies for junction identification.'
            transparent_path_junction: str
            'Specifies whether a transparent path junction is created. "yes" | "no".'
            mutual_auth: bool
            'Specifies whether to enforce mutual authentication between a front-end Reverse Proxy server and a back-end Reverse Proxy server over SSL. "yes" | "no".'
            insert_ltpa_cookie: bool
            ' Controls whether LTPA cookies are passed to the junctioned Web server. "yes" | "no"'
            insert_session_cookie: bool
            'Controls whether to send the session cookie to the junctioned Web server.'
            request_encoding: str
            'Specifies the encoding to use when the system generates HTTP headers for junctions.'
            enable_basic_auth: str
            'Specifies whether to use BA header information to authenticate to back-end server. "yes" | "no".'
            key_label: str
            'The key label for the client-side certificate that is used when the system authenticates to the junctioned Web server.'
            gso_resource_group: str
            'The name of the GSO resource or resource group.'
            junction_cookie_javascript_block: str
            'Controls the junction cookie JavaScript block. "trailer" | "inhead" | "onfocus" | "xhtml10" | "httpheader".'
            client_ip_http: str
            'Specifies whether to insert the IP address of the incoming request into an HTTP header for transmission to the junctioned Web server.'
            version_two_cookies: str
            'Specifies whether LTPA version 2 cookies (LtpaToken2) are used.'
            ltpa_keyfile: str
            'Location of the key file that is used to encrypt the LTPA cookie data.'
            ltpa_keyfile_password: str
            'Password for the key file that is used to encrypt LTPA cookie data.'
            authz_rules: str
            'Specifies whether to allow denied requests and failure reason information from authorization rules to be sent in the Boolean Rule header (AM_AZN_FAILURE) across the junction.'
            fss_config_file: str
            'The name of the configuration file that is used for forms based single sign-on.'
            username: str
            'The Reverse Proxy user name to send BA header information to the back-end server.'
            password: str
            'The Reverse Proxy password to send BA header information to the back-end server.'
            server_uuid: str
            'Specifies the UUID that will be used to identify the junctioned Web server.'
            virtual_hostname: str
            'Virtual host name that is used for the junctioned Web server.'
            server_dn: str
            'Specifies the distinguished name of the junctioned Web server.'
            server_cn: str
            'Specifies the common name, or subject alternative name, of the junctioned Web server.'
            local_ip: str
            'Specifies the local IP address that the Reverse Proxy uses when the system communicates with the target back-end server.'
            query_contents: str
            'Provides the Reverse Proxy with the correct name of the query_contents program file and where to find the file.'
            case_sensitive_url: str
            'Specifies whether the Reverse Proxy server treats URLs as case sensitive.'
            windows_style_url: str
            'Specifies whether Windows style URLs are supported.'
            proxy_hostname: str
            'The TCP port of the proxy server.'
            sms_environment: str
            'Only applicable for virtual junctions. Specifies the replica set that sessions on the virtual junction are managed under.'
            vhost_label: str
            'Only applicable for virtual junctions. Causes a second virtual junction to share the protected object space with the initial virtual junction.'
            force: bool
            'Specifies whether to overwrite an existing junction of the same name.'
            delegation_support: str
            'This option is valid only with junctions that were created with the type of ssl or sslproxy.'
            scripting_support: str
            'Supplies junction identification in a cookie to handle script-generated server-relative URLs.'
            junction_hard_limit: str
            'Defines the hard limit percentage for consumption of worker threads.'
            junction_soft_limit: str
            'Defines the soft limit percentage for consumption of worker threads.'
            https_port: str
            'HTTPS port of the back-end third-party server.'
            http_port: str
            'HTTP port of the back-end third-party server.'
            proxy_port: str
            'The TCP port of the proxy server.'
            remote_http_header: typing.List[str]
            'Controls the insertion of Security Verify Access specific client identity information in HTTP headers across the junction.'

        class Endpoint(typing.TypedDict):
            enabled: bool
            'Enable traffic on this endpoint.'
            port: typing.Optional[int]
            'Network port that endpoint should listen on.'

        class LDAP(typing.TypedDict):
            ssl: bool
            'Enable SSL Verification of connections.'
            key_file: typing.Optional[str]
            'The SSL Database to use to verify connections. Only valid if ``ssl == true``.'
            cert_file: typing.Optional[str]
            'The SSL Certificate to use to verify connections. Only valid of ``ssl == true``.'
            port: int
            'The network port to communicate with the LDAP server.'

        name: str
        'Name of the reverse proxy instance.'
        host: str
        'The host name that is used by the Security Verify Access policy server to contact the appliance.'
        nw_interface_yn: typing.Optional[str]
        'Specifies whether to use a logical network interface for the instance. only valid for applaince deployments. "yes" | "no".'
        ip_address: typing.Optional[str]
        'The IP address for the logical interface. Only valid for appliance deployments where ``nw_interface_yn == "yes"``. "yes" | "no".'
        listening_port: int
        'This is the listening port through which the instance communicates with the Security Verify Access policy server.'
        domain: str
        'The Security Verify Access domain.'
        ldap: LDAP
        'LDAP policy server properties.'
        http: Endpoint
        'HTTP traffic endpoint properties.'
        https: Endpoint
        'HTTPS traffic endpoint properties.'
        junctions: typing.Optional[typing.List[Junction]]
        'Junctions to backend resource servers for this reverse proxy instance.'
        aac_config: typing.Optional[AAC_Configuration]
        'Properties for configuring this reverse proxy instance for use with advanced access control authenticaiton and context based access service.'
        mmfa_config: typing.Optional[MMFA_Configuration]
        'Properties for configuring this reverse proxy instance to deliver MMFA capabilities.'
        federation: typing.Optional[Federation_Configuration]
        'Properties for integrating with a running Federation runtime.'
        stanza_configuration: typing.Optional[Stanza_Configuration]
        'List of modifications to perform on the webseald.conf configuration file for this reverse proxy instance.'

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



    class Runtime(typing.TypedDict):
        '''
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
        class LDAP(typing.TypedDict):
            host: str
            'Hostname or address for LDAP server.'
            port: int
            'Port LDAP server is listening on.'
            dn: str
            'Distinguished mane to bind to LDAP server for admin operations.'
            dn_password: str
            'Password to authenticate as ``dn``.'
            suffix: str
            'SecAuthority suffix.'
            key_file: str
            'SSL Database to use to verify connections to LDAP server.'
            cert_label: str
            'SSL Certificate label to verify connections to LDAP server.'

        class ISAM(typing.TypedDict):
            host: str
            'Hostname or address of Verify Access policy server.'
            port: int
            'Port that Verify Access policy server is listening on.'

        class Stanza_Configuration(typing.TypedDict):
            operation: str
            'Operation to perform on configuration file. "add" | "delete" | "update".'
            resource: str
            'Filename to be modified. "ldap.conf" | "pd.conf" | "instance.conf".'
            stanza: str
            'Name of stanza to modify.'
            entry: typing.Optional[str]
            'Optional entry_id to modify.'
            value: typing.Optional[str]
            'Optional value to modify.'

        policy_server: str
        'The mode for the policy server. "local" | "remote".'
        user_registry: str
        'Type of user registry to use. "local" | "ldap".'
        clean_ldap: bool
        'Remove any existing user data from registry. Only valid if ``user_registry == "local"``.'
        isam_domain: str
        'The Security Verify Access domain name.'
        admin_password: str
        'The password for the ``sec_master`` user.'
        admin_cert_lifetime: int
        'The lifetime in days for the SSL server certificate.'
        ssl_complaince: str
        'Specifies whether SSL is compliant with any additional computer security standard. "fips" | "sp800-131-transition" | "sp800-131-strict" | "suite-b-128" | "suite-b-192".'
        ldap: LDAP
        'LDAP server properties.'
        isam: typing.Optional[ISAM]
        'Verify Access policy server properties.'
        stanza_configuration: typing.Optional[typing.List[Stanza_Configuration]]
        'Optional list of modifications to configuration files.'

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
                        "ldap_ssl_label": runtime.ldap.cert_label
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
                pdadminCommands += ["acl modify {} set group {} {}".format(acl.name, group.name, group.permissions)]

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


    class PD_Admin(typing.TypedDict):
        '''
        Example::

                pdadmin:
                  users:
                    - username: "testuser"
                      password: "Passw0rd"
                      dn: "cn=testuser,dc=iswga"
                    - username: "aaascc"
                      password: "S3cr37"
                      dn: "cn=aaascc,dc=iswga"
                    - username: "ob_client"
                      password: "abcd1234"
                      dn: "cn=ob_client,dc=iswga"
                  reverse_proxies:
                    - host: "default-proxy"
                      acls:
                        - name: "isam_mobile_anyauth"
                          junctions:
                            - "/mga/sps/authsvc"
                            - "/mga/sps/apiauthsvc"
                            - "/intent/account-requests"
                        - name: "isam_mobile_rest_unauth"
                          junctions:
                            - "/mga/websock/mmfa-wss/"
                            - "/mga/sps/ac/info.js"
                            - "/mga/sps/ac/js/info.js"
                            - "/mga/sps/ac"
                            - "/.well-known"
                            - "/CertificateManagement/.well-known"
                            - "/mga/sps/mmfa/user/mgmt/qr_code"
                            - "/intent"
                        - name: "isam_mobile_unauth"
                          junctions:
                            - "/login"
                            - "/content"
                            - "/static"
                            - "/home"
                            - "/ob/sps/auth"
                        - name: "isam_mobile_rest"
                          junctions:
                            - "/scim"
                      pops:
                        - name: "oauth-pop"
                          junctions:
                            - "/scim"
                    - host: "default-proxy-mobile"
                      acls:
                        - name: "isam_rest_mobile"
                          junctions:
                            - "/scim"
                        - name: "isam_mobile_rest_unauth"
                          junctions:
                            - "/mga/sps/mmfa/user/mgmt/qr_code"
                      pops:
                        name: "oauth-pop"
                        junctions:
                          - "scim"

        '''

        class User(typing.TypedDict):
            username: str
            'The name the user will authenticate as. By default this is the UID LDAP attribte.'
            first_name: typing.Optional[str]
            'The CN LDAP attribute for this user. If not set then ``username`` will be used.'
            last_name: typing.Optional[str]
            'The SN LDAP attribute for this user. If not set then ``username`` will be used.'
            password: str
            'The secret to authenticate as ``username``.'
            dn: str
            'The DN LDAP attribute for this user.'

        class Group(typing.TypedDict):
            name: str
            'The CN LDAP attribute for this group.'
            dn: str
            'The DN LDAP attribute for this group.'
            description: typing.Optinal[str]
            'Optional description of group.'
            users: typing.Optional[typing.List[str]]
            'Optional list of users to add to group. These users must already exist in the user registry.'

        class Access_Control_List(typing.TypedDict):

            class Attribute(typing.TypedDict):
                name: str
                'Name of the ACL attribute'
                value: str
                'Value of the ACL attribute.'

            class Entity(typing.TypedDict):
                name: str
                'User or Group entity to set permissions for.'
                permissions: str
                'Permission bit-string, eg. "Tcmdbsvarxl"'

            name: str
            'Name of the ACL.'
            description: typing.Optional[str]
            'Optional description of the ACL'
            attributes: typing.Optional[typing.List[Attribute]]
            'List of extended attributes to add to ACL.'
            users: typing.Optional[typing.List[Entity]]
            'List of users and the permissions they are permitted to perform.'
            groups: typing.Optional[typing.List[Entity]]
            'List of groups and the permissions they are permitted to perform.'
            any_other: str
            'Permissions applied to users who do not match any of the defined user/group permissions.'
            unauthenticated: str
            'Permissions applied to unauthenticated users.'


        class Protected_Object_Policy(typing.TypedDict):

            class Attribute(typing.TypedDict):
                name: str
                'Name of the POP attribute.'
                value: str
                'value of the POP attribute.'

            class IP_Authorization(typing.TypedDict):
                class Network(typing.TypedDict):
                    network: str
                    'TCP/IP address to apply to this POP.'
                    netmask: str
                    'The corresponding netmask to apply to this POP.'
                    auth_level: str
                    'Required step-up authentication level.'

                any_other_network: str
                'Permissions for IP authentication not explicitly listed in the POP.'
                networks: typing.Optional[typing.List[Network]]
                'List of IP addresses to perform IP endpoint authentication.'

            name: str
            'Name of the POP.'
            description: typing.Optional[str]
            'Optional description of the POP.'
            attributes: typing.Optional[typing.List[Attribute]]
            'List of extended attribute to add to POP.'
            tod_access: str
            'Sets the time of day range for the specified protected object policy. '
            audit_level: str
            'Sets the audit level for the specified POP.'
            ip_auth: typing.Optional[typing.List[IP_Authorization]]
            'Sets the IP endpoint authentication settings in the specified POP.'

        class Reverse_Proxy(typing.TypedDict):
            class Reverse_Proxy_ACL(typing.TypedDict):
                name: str
                'Name of the ACL to attach to resources.'
                junctions: typing.List[str]
                'List of junction paths which use the specified ACL.'

            class Reverse_Proxy_POP(typing.TypedDict):
                name: str
                'Name of the POP to attach to resources.'
                junction: str
                'List of junction paths which use the specified POP.'

            host: str
            'Hostname use by the reverse proxy in the Policy Server\'s namespace.'
            acls: typing.Optional[typing.List[Reverse_Proxy_ACL]]
            'List of ACL\'s to attach to reverse proxy instance.'
            pops: typing.Optional[typing.List[Reverse_Proxy_POP]]
            'List of POP\'s to attach to reverse proxy instance.'

        users: typing.Optional[typing.List[User]]
        'List of users to add to the User Registry. These will be created as "full" Verify Access users.'
        groups: typing.Optional[typing.List[Group]]
        'List of grous to add to the User Registry. These will be created as "full" Verify Access groups.'
        acls: typing.Optional[typing.List[Access_Control_List]]
        'List of ACL\'s to create in the Policy Server.'
        pops: typing.optional[typing.List{Protected_Object_Policy]]
        'List of POP\'s to create in the Policy Server.'
        reverse_proxies: typing.Optional[typing.List[Reverse_Proxy]]
        'List of ACL\'s and POP\'s to attach to a WebSEAL reverse proxy instance.'


    def pdadmin(self, runtime, config):
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


    class Client_Certificate_Mapping(typing.TypedDict):
        '''
        Example::

                   client_cert_mapping:
                   - demo.mapping.xslt
                   - cert_to_uid.xlst

        '''

        client_cert_mapping: typing.List[str]
        'List of XSLT files to for matching X509 certificates from an incoming connection to an entity in the User Registry.'

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



    class Junction_Mapping(typing.TypedDict):
        '''
        Example::

                junction_mapping:
                - demo.jct.map
                - another.jct.map

        '''

        junction_mapping: typing.List[str]
        'List of properties file to map URI\'s to WebSEAL\'s object space.'


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


    class Url_Mapping(typing.TypedDict):
        '''
        Examples::

                  url-mapping:
                  - dyn.url.conf
                  - url.map.conf
        '''

        url_mapping: typing.List[str]
        'List of configuration files to re-map URL\'s.'

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


    class User_Mapping(typing.TypedDict):
        '''
        Example::

                  user_mapping:
                  - add_email.xslt
                  - federated_identity_to_basic_user.xslt

        '''
        user_mapping: typing.List[str]
        'List of XSLT files to be uploaded as user mapping rules.'

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


    class Form_Signle_Sign_On(typing.TypedDict):
        '''
        Example::

                fsso:
                - liberty_jsp_fsso.conf
                - fsso.conf

        '''
        fsso: typing.List[str]
        'List of configuration files to be uloaded as Form Single Sign-On rules.'

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


    class Http_Transformations(typing.TypedDict):
        '''
        Example::

                   http_transforms:
                   - inject_header.xslt
                   - eai.lua

        '''
        http_transforms: typing.List[str]
        'List of files to be uploaded as HTTP Transformation Rules. These can be either LUA rules using the ``.lua`` file extension or XSLT rules using the ``.xslt`` file extension.'

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


    class Kerberos(typing.TypedDict):
        '''
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
        class Realm(typing.TypedDict):
            name: str
            'Name of the Kerberos realm.'
            properties: typing.Optional[typing.List[typing.Dict]]
            'List of key\: value properties to configure for realm.'

        class Domain_Realm(typing.TypedDict):
            name: str
            'Name of the Domain Realm.'
            dns: str
            'DNS server for the Domain Realm.'

        libdefaults: typing.Optional[typing.List[typing.Dict]]
        'List of key: value properties to configure as defaults.'
        realms: typing.Optional[typing.List[Realm]]
        'List of Kerberos Realm\'s to configure.'
        domain_realms: typing.Optional[typing.List[Domain_Realm]]
        'List of Kerberos DOmain Realm\'s to configure.'
        keytabs: typing.Optional[typing.List[str]]
        'List of files to import as Kerbros Keytab files.'
        capaths: typing.Dict
        'TODO.'

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


    class Password_Strength(typing.TypedDict):
        '''
        Example::

                   password_strength:
                   - demo_rule.xlst

        '''
        password_strength: typing.List[str]
        'List of XSLT file to be uploaded as password strength checks.'

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


    class RSA(typing.TypedDict):
        '''
        Example::

                   rsa_config:
                     server_config: server.conf
                     optional_server_config: optional_server.conf

        '''
        server_config: str
        'The server configuration file to upload.'
        optional_server_config: str
        'The server configuration options file to upload.'

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

    def __apiac_policies(self, policies):
        for policy in policies:
            rsp = self.web.api_access_control.policies.create(name=policy.name, groups=policy.groups, 
                                                              attributes=policy.attributes)
            if rsp.success == True:
                _logger.info("Successfully created {} policy".format(policy.name))
            else:
                _logger.error("Failed to create API Access Control policy {}:\n{}\n{}".format(policy.name,
                                                                            json.dumps(policy, indent=4), rsp.content))

    def __apiac_cors(self, cors_policies):
        for cors in cors_policies:
            rsp = self.web.api_access_control.cors.create(**cors)
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


    class Api_Access_Control(typing.TypedDict):
        '''
        Example::

                api_access_control:
                  authz_servers:
                  - name: "authz_server"
                    hostname: "isvaconfig"
                    document_root:
                    - webseal_root.zip
                    resources:
                    - name: "api_ac_instance"
                      hostname: "TODO"
                  cors:
                  - name:
                    allowed_origins
                    allowed_credentials
                    exposed_headers
                    handle_preflight
                    allowed_methods
                    allowed_headers:
                    max_age:


        '''
        class Authorization_Server(typing.TypedDict):

            class Resource(typing.TypedDict):
                server_hostname: str
                juntion_point: str

            name: str
            hostname: str
            auth_port: int
            admin_port: int
            domain: str
            addresses: typing.Optional[typing.List[str]]
            ssl: str
            ssl_port: str
            key_file: str
            key_label: str
            resources: typing.Optional[typing.List[Resource]]
            document_root: typing.Optional[typing.List[str]]

        class Policy(typing.TypedDict):
            name: str
            groups: typing.List[str]
            attributes: typing.List[str]

        class Cross_Origin_Resource_Sharing(typing.TypedDict):
            name: str
            allowed_origin: typing.Optional[typing.List[str]]
            allowed_credentials: typing.Optional[typing.List[str]]
            exposed_headers: typing.Optional[typing.List[str]]
            handle_preflight: bool
            allowed_methods: typing.Optional[typing.List[str]]
            allowed_headers: typing.Optional[typing.List[str]]
            max_age: int

        authz_servers: typing.Optional[typing.List[Authorization_Server]]
        policies: typing.Optional[typing.List[Policy]]
        cors: typing.Optional[typing.List[Cross_Origin_Resource_Sharing]]


    def api_access_control(self, runtime, config):
        rsp = self.web.api_access.control.utilities.store_credential(admin_id=runtime.admin_user,
                admin_pwd=runtime.admin_password, admin_doman=runtime.domain)
        if rsp.success == True:
            _logger.info("API Access Control successfully stored admin credential")
        else:
            _logger.error("API Access Control was unable to store admin credential")
            return
        if config.authz_servers != None:
            for auth_server in config.authz_servers:
                rsp = self.web.api_access_control.authz_server.create_server(auth_server.name, hostname=auth_server.hostname,
                            auth_port=auth_server.auth_port, admin_port=auth_server.admin_port, domain=auth_server.domain,
                            admin_id="sec_master", admin_pwd=runtime.admin_password, addresses=auth_server.addresses,
                            ssl=auth_server.ssl, ssl_port=auth_server.ssl_port, keyfile=auth_server.key_file, 
                            keyfile_label=auth_server.key_label)
                if rsp.success == True:
                    _logger.info("Successfully created {} API authorization server".format(auth_server.name))
                else:
                    _logger.error("Failed to create the {} API authorization server;\n{}\n{}".format(auth_server.name,
                                                                            json.dumps(auth_server, indent=4), rsp.content))
                    continue

                if auth_server.document_root != None:
                    self.__apiac_document_root(auth_server.document_root)

                if auth_server.resources != None:
                    self.__apiac_resources(auth_server.resources)

        if config.policies != None:
            self.__apiac_policies(config.policies)

        if config.cors != None:
            self.__apiac_cors(config.cors)


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

            if webseal.authroization_servers != None:
                self.api_access_control(websealConfig.runtime, websealConfig.authroization_server)

            if websealConfig.pdadmin != None:
                self.pdadmin(websealConfig.runtime, websealConfig.pdadmin)

        else:
            _logger.info("No runtime configuration detected, unable to set up any reverse proxy config or run pdadmin commands")


if __name__ == "__main__":
        configure()
