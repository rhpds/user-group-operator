import asyncio
import copy
import kopf
import kubernetes
import ldap3
import logging
import os
import re
import simple_salesforce
import ssl
import tempfile
import threading
import time

from base64 import b64decode
from hashlib import sha256

from configure_kopf_logging import configure_kopf_logging
from infinite_relative_backoff import InfiniteRelativeBackoff

operator_domain = os.environ.get('OPERATOR_DOMAIN', 'usergroup.pfe.redhat.com')
operator_version = os.environ.get('OPERATOR_VERSION', 'v1')

if os.path.exists('/run/secrets/kubernetes.io/serviceaccount/token'):
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()

core_v1_api = kubernetes.client.CoreV1Api()
custom_objects_api = kubernetes.client.CustomObjectsApi()


class Group:
    @staticmethod
    def add_user(group_name, user_name, logger):
        try:
            group = Group.get(group_name)
            if group:
                if user_name in group.users:
                    return group
                else:
                    definition = custom_objects_api.replace_cluster_custom_object(
                        'user.openshift.io', 'v1', 'groups', group_name,
                        {
                            "apiVersion": "user.openshift.io/v1",
                            "kind": "Group",
                            "metadata": group.metadata,
                            "users": group.users + [user_name],
                        }
                    )
                    logger.info(f"Addded {user_name} to group {group_name}")
                    return Group(definition)
            else:
                definition = custom_objects_api.create_cluster_custom_object(
                    'user.openshift.io', 'v1', 'groups',
                    {
                        "apiVersion": "user.openshift.io/v1",
                        "kind": "Group",
                        "metadata": {
                            "name": group_name,
                        },
                        "users": [user_name],
                    }
                )
                logger.info(f"Created group {group_name} with first user {user_name}")
                return Group(definition)
        except kubernetes.client.rest.ApiException as e:
            if e.status == 409:
                raise kopf.TemporaryError(f"Conflict while adding {user_name} to {group_name}", delay=1)
            else:
                raise

    @staticmethod
    def get(group_name):
        try:
            definition = custom_objects_api.get_cluster_custom_object(
                'user.openshift.io', 'v1', 'groups', group_name
            )
            return Group(definition)
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                raise

    @staticmethod
    def get_or_create(group_name):
        try:
            group = Group.get(group_name)
            if not group:
                group = Group(
                    custom_objects_api.create_cluster_custom_object(
                        'user.openshift.io', 'v1', 'groups',
                        {
                            "apiVersion": "user.openshift.io/v1",
                            "kind": "Group",
                            "metadata": {
                                "name": group_name,
                            },
                            "users": [],
                        }
                    )
                )
            return group
        except kubernetes.client.rest.ApiException as e:
            if e.status == 409:
                raise kopf.TemporaryError(f"Conflict while creating group {group_name}", delay=1)
            else:
                raise

    @staticmethod
    def remove_user(group_name, user_name, logger):
        attempt = 0
        while True:
            attempt += 1
            try:
                group = Group.get(group_name)
                if not group:
                    return
                if user_name not in group.users:
                    return
                custom_objects_api.replace_cluster_custom_object(
                    'user.openshift.io', 'v1', 'groups', group_name,
                    {
                        "apiVersion": "user.openshift.io/v1",
                        "kind": "Group",
                        "metadata": group.metadata,
                        "users": [name for name in group.users if name != user_name],
                    }
                )
                logger.info(f"Removed {user_name} from group {group_name}")
                return
            except kubernetes.client.rest.ApiException as e:
                if attempt > 3:
                    raise

    def __init__(self, definition):
        self.metadata = definition['metadata']
        self.users = definition.get('users')

    @property
    def name(self):
        return self.metadata['name']

    @property
    def uid(self):
        return self.metadata['uid']

    @property
    def ref(self):
        return {
            "apiVersion": "user.openshift.io/v1",
            "kind": "Group",
            "name": self.metadata['name'],
            "uid": self.metadata['uid'],
        }


class Identity:
    @staticmethod
    def get(name, retries=0, retry_delay=1):
        while True:
            try:
                definition = custom_objects_api.get_cluster_custom_object(
                    'user.openshift.io', 'v1', 'identities', name
                )
                return Identity(definition)
            except kubernetes.client.rest.ApiException as e:
                if retries > 0:
                    time.sleep(retry_delay)
                    retries -= 1;
                else:
                    raise

    def __init__(self, definition):
        self.extra = definition.get('extra', {})
        self.metadata = definition['metadata']
        self.provider_name = definition.get('providerName')
        self.provider_user_name = definition.get('providerUserName')
        self.user = definition.get('user')

    @property
    def email(self):
        return self.extra.get('email')

    @property
    def name(self):
        return self.metadata['name']

    @property
    def ref(self):
        return {
            "apiVersion": "user.openshift.io/v1",
            "kind": "Identity",
            "name": self.metadata['name'],
            "uid": self.metadata['uid'],
        }

    @property
    def uid(self):
        return self.metadata['uid']


class User:
    def __init__(self, definition, logger=None):
        self.identities = definition.get('identities')
        self.metadata = definition['metadata']

    @property
    def name(self):
        return self.metadata['name']

    @property
    def ref(self):
        return {
            "apiVersion": "user.openshift.io/v1",
            "kind": "User",
            "name": self.metadata['name'],
            "uid": self.metadata['uid'],
        }

    @property
    def uid(self):
        return self.metadata['uid']

    def get_identities(self, logger, retries=0, retry_delay=1):
        if not self.identities:
            return []
        identities = []
        for identity_name in self.identities:
            identities.append(Identity.get(identity_name, retries=3, retry_delay=0.5))
        return identities

    def manage_groups(self, logger):
        for config in UserGroupConfig.list():
            config.manage_user_group_members(self, logger)


class UserGroupConfig:
    __configs = {}

    @staticmethod
    def get(name):
        return UserGroupConfig.__configs.get(name)

    @staticmethod
    def list():
        return UserGroupConfig.__configs.values()

    @staticmethod
    def register(name, **kwargs):
        config = UserGroupConfig.__configs.get(name)
        if config:
            config.__init__(name=name, **kwargs)
        else:
            config = UserGroupConfig(name=name, **kwargs)
            UserGroupConfig.__configs[name] = config
        return config

    def __init__(self, name, spec):
        self.name = name
        self.spec = spec
        self.ldap = [
            UserGroupConfigLDAP(item) for item in spec['ldap']
        ] if 'ldap' in self.spec else []
        self.salesforce = [
            UserGroupConfigSalesforce(item) for item in spec['salesforce']
        ] if 'salesforce' in self.spec else []
        self._lock = threading.Lock()

    @property
    def email_domain_groups_enabled(self):
        return self.spec.get('emailDomainGroups', {}).get('enable', False)

    @property
    def email_domain_groups_prefix(self):
        return self.spec.get('emailDomainGroups', {}).get('prefix', 'email-domain.')

    @property
    def identity_provider_groups_enabled(self):
        return self.spec.get('identityProviderGroups', {}).get('enable', False)

    @property
    def identity_provider_groups_prefix(self):
        return self.spec.get('identityProviderGroups', {}).get('prefix', 'identity-provider.')

    @property
    def refresh_interval(self):
        return int(self.spec.get('refresh_interval', 3600))

    def cleanup_on_delete(self, logger):
        _continue = None
        user_group_member_names = []
        while True:
            user_group_member_list = custom_objects_api.list_cluster_custom_object(
                operator_domain, operator_version, 'usergroupmembers',
                _continue = _continue,
                label_selector = f"usergroup.pfe.redhat.com/config={self.name}",
                limit = 50,
            )
            user_group_member_names.extend([
                item['metadata']['name'] for item in user_group_member_list['items']
            ])
            _continue = user_group_member_list['metadata'].get('continue')
            if not _continue:
                break

        for user_group_member_name in user_group_member_names:
            logger.info(f"Cleanup UserGroupMember {user_group_member_name} on UserGroupConfig deletion")
            user_group_member_list = custom_objects_api.delete_cluster_custom_object(
                operator_domain, operator_version, 'usergroupmembers', user_group_member_name
            )

    def manage_user_group_members(self, user, logger):
        logger.info(f"Managing user {user.name}")
        group_names = set()

        for identity in user.get_identities(logger=logger):
            identity_group_names = set()

            if self.identity_provider_groups_enabled:
                identity_group_names.add(
                    self.identity_provider_groups_prefix + identity.provider_name
                )

            if self.email_domain_groups_enabled:
                email = identity.email
                if email and '@' in email:
                    domain = email.split('@')[1]
                    identity_group_names.add(
                        self.email_domain_groups_prefix + domain
                    )

            for ldap in self.ldap:
                if not ldap.identity_provider_name \
                or ldap.identity_provider_name == identity.provider_name:
                    identity_group_names.update(
                        ldap.get_group_names(user, identity, logger)
                    )

            for salesforce in self.salesforce:
                if not salesforce.identity_provider_name \
                or salesforce.identity_provider_name == identity.provider_name:
                    identity_group_names.update(
                        salesforce.get_group_names(user, identity, logger)
                    )

            for group_name in identity_group_names:
                UserGroupMember.create(
                    config = self,
                    group_name = group_name,
                    identity = identity,
                    logger = logger,
                    user = user,
                )

            group_names.update(identity_group_names)

        for user_group_member_definition in custom_objects_api.list_cluster_custom_object(
            operator_domain, operator_version, 'usergroupmembers',
            label_selector = f"usergroup.pfe.redhat.com/config={self.name},usergroup.pfe.redhat.com/user-uid={user.uid}",
        ).get('items', []):
            name = user_group_member_definition['metadata']['name']
            group_name = user_group_member_definition['spec']['group']['name']
            if group_name not in group_names:
                logger.info(f"Cleanup UserGroupMember {name}")
                user_group_member_list = custom_objects_api.delete_cluster_custom_object(
                    operator_domain, operator_version, 'usergroupmembers', name
                )

    def manage_groups(self, logger):
        with self._lock:
            self._manage_groups(logger)

    def _manage_groups(self, logger):
        _continue = None
        last_processed_user_name = None
        while True:
            try:
                user_list = custom_objects_api.list_cluster_custom_object(
                    'user.openshift.io', 'v1', 'users',
                    _continue = _continue,
                    limit = 50,
                )
                for user_definition in user_list.get('items', []):
                    user = User(user_definition)
                    if last_processed_user_name and last_processed_user_name >= user.name:
                        continue
                    else:
                        last_processed_user_name = user.name
                    self.manage_user_group_members(user, logger)
                _continue = user_list['metadata'].get('continue')
                if not _continue:
                    break
            except kubernetes.client.rest.ApiException as e:
                if e.status == 410:
                    # Query expired before completion, reset.
                    logger.info("Restarting user list for group management")
                    _continue = None
                else:
                    raise

    def unregister(self):
        return UserGroupConfig.__configs.pop(self.name)


class UserGroupConfigLDAP:
    ldapUrlRegex = re.compile(r'^(ldaps?)://([^:]+)(?::(\d+))?$')

    def __init__(self, definition):
        self.attribute_to_group = [
            UserGroupConfigLDAPAttributeToGroup(item) for item in definition['attributeToGroup']
        ] if 'attributeToGroup' in definition else None
        self.auth_secret = UserGroupConfigLDAPAuthSecret(definition['authSecret'])
        self.ca_cert = definition.get('caCert')
        self.identity_provider_name = definition.get('identityProviderName')
        self.insecure = definition.get('insecure', False)
        self.url = definition['url']
        self.user_base_dn = definition['userBaseDN']
        self.user_object_class = definition.get('userObjectClass', 'inetOrgPerson')
        self.user_search_attribute = definition.get('userSearchAttribute', 'uid')
        self.user_search_value = definition.get('userSearchValue', 'name')

    @property
    def bind_dn(self):
        return self.auth_secret.bind_dn

    @property
    def bind_password(self):
        return self.auth_secret.bind_password

    @property
    def ca_cert_file(self):
        if not self.ca_cert:
            return None
        file_path = os.path.join('/tmp', sha256(self.ca_cert.encode('utf-8')).hexdigest())
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(self.ca_cert)
        return file_path

    def get_group_names(self, user, identity, logger):
        group_names = set()

        # If restricted to an identity provider then check match
        if self.identity_provider_name \
        and self.identity_provider_name != identity.provider_name:
            return group_names

        search_value = user.name if self.user_search_value == 'name' else identity.extra.get(self.user_search_value)
        if not search_value:
            return group_names

        connection = self.ldap_connect()

        user_object_def = ldap3.ObjectDef(self.user_object_class, connection)
        if not hasattr(user_object_def, self.user_search_attribute):
            user_object_def += self.user_search_attribute
        if self.attribute_to_group:
            for attribute in self.attribute_to_group:
                if not hasattr(user_object_def, attribute.attribute):
                    user_object_def += attribute.attribute

        reader = ldap3.Reader(
            connection, user_object_def, self.user_base_dn,
            f"{self.user_search_attribute}:={search_value}"
        )
        reader.search()
        if len(reader) == 0:
            return group_names

        group_names = set()
        ldap_user = reader[0]

        for attribute_to_group in self.attribute_to_group:
            try:
                values = reader[0][attribute.attribute].values
                for value in values:
                    value = str(value)
                    if value.startswith('cn='):
                        cn = value[3:].split(',', 1)[0]
                        default_group_name = f"ldap-{attribute.attribute}-{cn}"
                    else:
                        default_group_name = f"ldap-{attribute.attribute}-{value}"
                    if attribute_to_group.value_to_group:
                        for value_to_group in attribute_to_group.value_to_group:
                            if value == value_to_group.value:
                                group_names.update(value_to_group.get_groups(default_group_name))
                    else:
                        group_names.add(default_group_name)
            except ldap3.core.exceptions.LDAPKeyError:
                logging.warn(f"{ldap_user.entry_dn} has no attribute {attribute.attribute}")

        return group_names

    def ldap_connect(self):
        protocol, server, port = self.ldapUrlRegex.match(self.url).groups()
        if port:
            port = int(port)
        else:
            port = 636 if protocol == 'ldaps' else 389

        server = ldap3.Server(
            server,
            tls = ldap3.Tls(
                ca_certs_file = self.ca_cert_file,
                validate = ssl.CERT_NONE if self.insecure else ssl.CERT_REQUIRED,
                version = ssl.PROTOCOL_TLSv1
            ),
            use_ssl = protocol == 'ldaps',
        )

        connection = ldap3.Connection(server, self.bind_dn, self.bind_password)

        if protocol == 'ldap' and not self.insecure:
            connection.start_tls()

        connection.bind()
        return connection


class UserGroupConfigLDAPAttributeToGroup:
    def __init__(self, definition):
        self.attribute = definition['attribute']
        self.value_to_group = [
            UserGroupConfigLDAPAttributeValueToGroup(item) for item in definition['valueToGroup']
        ] if 'valueToGroup' in definition else None


class UserGroupConfigLDAPAttributeValueToGroup:
    def __init__(self, definition):
        self.group = definition.get('group')
        self.groups = definition.get('groups')
        self.value = definition['value']

    def get_groups(self, default_group_name):
        if self.group == None and self.groups == None:
            return default_group_name
        else:
            return (self.groups or []) + ([self.group] if self.group else [])


class UserGroupConfigLDAPAuthSecret:
    def __init__(self, definition):
        self.name = definition['name']
        self._bind_dn = None
        self._bind_password = None
        self._lock = threading.Lock()
        if 'namespace' in definition:
            self.namespace = definition['namespace']
        else:
            try:
                # Try getting namespace within cluster
                with open('/run/secrets/kubernetes.io/serviceaccount/namespace') as f:
                    self.namespace = f.read()
            except FileNotfoundError:
                # Running locally?
                self.namespace = kubernetes.config.list_kube_config_contexts()[1]['context']['namespace']

    @property
    def bind_dn(self):
        if self._bind_dn:
            return self._bind_dn
        with self._lock:
            if not self._bind_dn:
                self._read_secret()
        return self._bind_dn

    @property
    def bind_password(self):
        if self._bind_password:
            return self._bind_password
        with self._lock:
            if not self._bind_password:
                self._read_secret()
            return self._bind_password

    def _read_secret(self):
        '''
        Attempt to read LDAP secret with retries in case the configuration was created befor the secret.
        '''
        attempt = 0
        while True:
            try:
                secret = core_v1_api.read_namespaced_secret(self.name, self.namespace)
                self._bind_dn = b64decode(secret.data['bindDN']).decode('utf-8')
                self._bind_password = b64decode(secret.data['bindPassword']).decode('utf-8')
                return
            except kubernetes.client.rest.ApiException as e:
                if e.status == 404 and attempt < 10:
                    attempt += 1
                    time.sleep(0.5)
                else:
                    raise


class UserGroupConfigSalesforce:
    def __init__(self, definition):
        self.consumer_key = definition['consumerKey']
        self.consumer_secret = UserGroupConfigSalesforceConsumerSecret(definition['consumerSecret'])
        self.field_to_group = [
            UserGroupConfigSalesforceFieldToGroup(item) for item in definition['fieldToGroup']
        ] if 'fieldToGroup' in definition else None
        self.identity_provider_name = definition.get('identityProviderName')
        self.url = definition.get('url', 'https://login.salesforce.com')
        self.user_search_field = definition.get('userSearchField', 'federationId')
        self.user_search_value = definition.get('userSearchValue', 'name')
        self.username = definition['username']

    def get_group_names(self, user, identity, logger):
        group_names = set()

        # If restricted to an identity provider then check match
        if self.identity_provider_name \
        and self.identity_provider_name != identity.provider_name:
            return group_names

        search_value = user.name if self.user_search_value == 'name' else identity.extra.get(self.user_search_value)
        if not search_value:
            return group_names

        salesforce_api = self.salesforce_api()
        salesforce_user = salesforce_api.apexecute(f"vendor/user/lookup?{self.user_search_field}={search_value}", method='GET')

        for field_to_group in self.field_to_group:
            value = salesforce_user.get(field_to_group.name)
            default_group_name = f"salesforce-{field_to_group.name}-{value}"
            if not value:
                continue
            if field_to_group.value_to_group:
                for value_to_group in field_to_group.value_to_group:
                    if value == value_to_group.value:
                        group_names.update(value_to_group.get_groups(default_group_name))
            else:
                group_names.add(default_group_name)

        return group_names

    def salesforce_api(self):
        return simple_salesforce.Salesforce(
            instance_url = self.url,
            username = self.username,
            consumer_key = self.consumer_key,
            privatekey_file = self.consumer_secret.file_path,
        )


class UserGroupConfigSalesforceConsumerSecret:
    def __init__(self, definition):
        self.name = definition['name']
        self._tempfile = None
        self._lock = threading.Lock()
        if 'namespace' in definition:
            self.namespace = definition['namespace']
        else:
            try:
                # Try getting namespace within cluster
                with open('/run/secrets/kubernetes.io/serviceaccount/namespace') as f:
                    self.namespace = f.read()
            except FileNotfoundError:
                # Running locally?
                self.namespace = kubernetes.config.list_kube_config_contexts()[1]['context']['namespace']

    def __del__(self):
        if self._tempfile:
            os.unlink(self._tempfile.name)

    @property
    def file_path(self):
        if self._tempfile:
            return self._tempfile.name
        with self._lock:
            if not self._tempfile:
                self._read_secret_to_tempfile()
        return self._tempfile.name

    def _read_secret_to_tempfile(self):
        '''
        Attempt to read Salesforce client secret with retries in case the configuration was created befor the secret.
        '''
        attempt = 0
        while True:
            try:
                secret = core_v1_api.read_namespaced_secret(self.name, self.namespace)
                secret_keys = secret.data.keys()
                if secret_keys == 1:
                    client_secret_key = secret_keys[1]
                elif 'tls.key' in secret_keys:
                    client_secret_key = 'tls.key'
                else:
                    raise Exception(f"Salesforce client secret {self.name} in {self.namespace} has more than one data item and no tls.key!")
                self._tempfile = tempfile.NamedTemporaryFile(delete=False)
                self._tempfile.write(b64decode(secret.data[client_secret_key]))
                self._tempfile.close()
                return
            except kubernetes.client.rest.ApiException as e:
                if e.status == 404 and attempt < 10:
                    attempt += 1
                    time.sleep(0.5)
                else:
                    raise


class UserGroupConfigSalesforceFieldToGroup:
    def __init__(self, definition):
        self.name = definition['name']
        self.value_to_group = [
            UserGroupConfigSalesforceFieldValueToGroup(item) for item in definition['valueToGroup']
        ] if 'valueToGroup' in definition else None


class UserGroupConfigSalesforceFieldValueToGroup:
    def __init__(self, definition):
        self.group = definition.get('group')
        self.groups = definition.get('groups')
        self.value = definition['value']

    def get_groups(self, default_group_name):
        if self.group == None and self.groups == None:
            return default_group_name
        else:
            return (self.groups or []) + ([self.group] if self.group else [])


class UserGroupMember:
    @staticmethod
    def create(config, group_name, identity, logger, user):
        group = Group.get(group_name)
        name = f"{group_name.lower()}.{user.uid}"
        try:
            definition = {
                "apiVersion": "usergroup.pfe.redhat.com/v1",
                "kind": "UserGroupMember",
                "metadata": {
                    "name": name,
                    "annotations": {
                        "usergroup.pfe.redhat.com/group-name": group_name,
                        "usergroup.pfe.redhat.com/identity-name": identity.name,
                        "usergroup.pfe.redhat.com/user-name": user.name,
                    },
                    "labels": {
                        "usergroup.pfe.redhat.com/config": config.name,
                        "usergroup.pfe.redhat.com/identity-uid": identity.uid,
                        "usergroup.pfe.redhat.com/user-uid": user.uid,
                    },
                    "ownerReferences": [{
                        "blockOwnerDeletion": False,
                        "controller": True,
                        **user.ref,
                    }]
                },
                "spec": {
                    "group": group.ref if group else {
                        "apiVersion": "user.openshift.io/v1",
                        "kind": "Group",
                        "name": group_name,
                    },
                    "identity": identity.ref,
                    "user": user.ref,
                }
            }
            if group:
                definition['metadata']['labels']['usergroup.pfe.redhat.com/group-uid'] = group.uid
            custom_objects_api.create_cluster_custom_object('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', definition)
            logger.info(f"Created UserGroupMember {name}")
        except kubernetes.client.rest.ApiException as e:
            if e.status != 409:
                raise

    def __init__(self, definition):
        self.metadata = definition['metadata']
        self.spec = definition['spec']

    @property
    def group_name(self):
        return self.spec['group']['name']


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    # Store last handled configuration in status
    settings.persistence.diffbase_storage = kopf.StatusDiffBaseStorage(field='status.diffBase')

    # Never give up from network errors
    settings.networking.error_backoffs = InfiniteRelativeBackoff()

    # Use operator domain as finalizer
    settings.persistence.finalizer = operator_domain

    # Store progress in status.
    settings.persistence.progress_storage = kopf.StatusProgressStorage(field='status.kopf')

    # Only create events for warnings and errors
    settings.posting.level = logging.WARNING

    # Disable scanning for CustomResourceDefinitions updates
    settings.scanning.disabled = True

    # Configure logging
    configure_kopf_logging()

    # Preload all UserGroupConfig definitions
    for definition in custom_objects_api.list_cluster_custom_object(
        operator_domain, operator_version, 'usergroupconfigs'
    ).get('items'):
        UserGroupConfig.register(
            name = definition['metadata']['name'],
            spec = definition['spec'],
        )


@kopf.on.event('user.openshift.io', 'v1', 'users')
def user_handler(event, logger, **_):
    if event['type'] in ['ADDED', 'MODIFIED', None]:
        user = User(event['object'], logger)
        user.manage_groups(logger)


@kopf.on.create('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs', id='usergroupconfig_create')
@kopf.on.resume('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs', id='usergroupconfig_resume')
@kopf.on.update('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs', id='usergroupconfig_update')
def usergroupconfig_event(name, spec, logger, **_):
    config = UserGroupConfig.register(name=name, spec=spec)
    config.manage_groups(logger)

@kopf.daemon('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs', cancellation_timeout=1)
async def usergroupconfig_daemon(stopped, name, spec, logger, **_):
    config = UserGroupConfig.register(name=name, spec=spec)
    try:
        while True:
            await asyncio.sleep(config.refresh_interval)
            if stopped:
                break
            else:
                config.manage_groups(logger)
    except asyncio.CancelledError:
        pass

@kopf.on.delete('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs')
def usergroupmember_delete(name, spec, logger, **_):
    config = UserGroupConfig(name=name, spec=spec)
    config.cleanup_on_delete(logger)
    config.unregister()


@kopf.on.create('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', id='usergroupmember_create')
@kopf.on.resume('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', id='usergroupmember_resume')
@kopf.on.update('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', id='usergroupmember_update')
def usergroupmember_event(name, labels, meta, spec, logger, **_):
    group = Group.add_user(
        spec['group']['name'],
        spec['user']['name'],
        logger,
    )
    if 'uid' not in spec['group'] or 'usergroup.pfe.redhat.com/group-uid' not in labels:
        custom_objects_api.patch_cluster_custom_object(
            operator_domain, operator_version, "usergroupmembers", name,
            {
                "metadata": {
                    "labels": {
                        "usergroup.pfe.redhat.com/group-uid": group.uid,
                    }
                },
                "spec": {
                    "group": group.ref,
                }
            }
        )

@kopf.on.delete('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers')
def usergroupmember_delete(spec, logger, **_):
    Group.remove_user(
        spec['group']['name'],
        spec['user']['name'],
        logger,
    )
