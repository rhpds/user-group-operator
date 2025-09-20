import asyncio
import json
import logging
import os
import re
import ssl
import tempfile
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from time import time

import aiohttp
import jmespath
import kopf
import kubernetes_asyncio
import ldap3
import simple_salesforce
import yaml
from configure_kopf_logging import configure_kopf_logging
from infinite_relative_backoff import InfiniteRelativeBackoff
from simplejinja import check_condition, jinja2process

operator_domain = os.environ.get('OPERATOR_DOMAIN', 'usergroup.pfe.redhat.com')
operator_version = os.environ.get('OPERATOR_VERSION', 'v1')
operator_start_datetime = datetime.now(timezone.utc)

class Operator:
    api_client = None
    core_v1_api = None
    custom_objects_api = None
    operator_namespace = None

    @classmethod
    async def on_startup(cls):
        if os.path.exists('/run/secrets/kubernetes.io/serviceaccount/token'):
            kubernetes_asyncio.config.load_incluster_config()
            with open('/run/secrets/kubernetes.io/serviceaccount/namespace', encoding='utf-8') as f:
                cls.operator_namespace = f.read()
        else:
            await kubernetes_asyncio.config.load_kube_config()
            cls.operator_namespace = kubernetes_asyncio.config.list_kube_config_contexts()[1]['context']['namespace']

        cls.api_client = kubernetes_asyncio.client.ApiClient()
        cls.core_v1_api = kubernetes_asyncio.client.CoreV1Api(cls.api_client)
        cls.custom_objects_api = kubernetes_asyncio.client.CustomObjectsApi(cls.api_client)

    await UserGroupConfig.preload()

class Group:
    instances = {}
    lock = asyncio.Lock()

    @staticmethod
    async def get(group_name, init_new=False):
        async with Group.lock:
            if group_name in Group.instances:
                return Group.instances[group_name]
            try:
                definition = await Operator.custom_objects_api.get_cluster_custom_object(
                    'user.openshift.io', 'v1', 'groups', group_name
                )
                group = Group(definition)
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404 and init_new:
                    group = Group({"metadata": {"name": group_name}})
                else:
                    raise
            Group.instances[group.name] = group
            return group

    @staticmethod
    async def register(definition):
        async with Group.lock:
            name = definition['metadata']['name']
            group = Group.instances.get(name)
            if group:
                group.__init__(definition)
            else:
                group = Group(definition)
                Group.instances[group.name] = group
            return group

    @staticmethod
    async def unregister(name):
        async with Group.lock:
            return Group.instances.pop(name, None)

    def __init__(self, definition):
        self.definition = definition
        self.lock = asyncio.Lock()

    @property
    def metadata(self):
        return self.definition['metadata']

    @property
    def name(self):
        return self.metadata['name']

    @property
    def ref(self):
        ret = {
            "apiVersion": "user.openshift.io/v1",
            "kind": "Group",
            "name": self.name,
        }
        if self.uid:
            ret['uid'] = self.uid
        return ret

    @property
    def uid(self):
        return self.metadata.get('uid')

    @property
    def users(self):
        return self.definition.get('users', [])

    async def add_user(self, user_name, logger, retries=10):
        async with self.lock:
            attempt = 0
            while True:
                try:
                    if attempt > 0:
                        await self.refresh(logger=logger)
                    if user_name in self.users:
                        return
                    if self.uid:
                        definition = await Operator.custom_objects_api.replace_cluster_custom_object(
                            'user.openshift.io', 'v1', 'groups', self.name,
                            {
                                "apiVersion": "user.openshift.io/v1",
                                "kind": "Group",
                                "metadata": self.metadata,
                                "users": self.users + [user_name],
                            }
                        )
                        logger.info(f"Added {user_name} to group {self.name}")
                    else:
                        definition = await Operator.custom_objects_api.create_cluster_custom_object(
                            'user.openshift.io', 'v1', 'groups',
                            {
                                "apiVersion": "user.openshift.io/v1",
                                "kind": "Group",
                                "metadata": {
                                    "name": self.name,
                                },
                                "users": [user_name],
                            }
                        )
                        logger.info(f"Created group {self.name} with first user {user_name}")
                    self.__init__(definition)
                    return
                except kubernetes_asyncio.client.exceptions.ApiException as e:
                    if e.status == 404:
                        # No group? Update metadata to indicate need to create it
                        self.metadata['uid'] = None
                    elif e.status == 409 and attempt < retries:
                        # Conflict, refresh from API and retry
                        attempt += 1
                    else:
                        raise

    async def refresh(self, logger):
        try:
            definition = await Operator.custom_objects_api.get_cluster_custom_object(
                'user.openshift.io', 'v1', 'groups', self.name,
            )
            self.__init__(definition)
            logger.info(f"Refreshed group {self.name}")
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status == 404:
                Group.unregister(self.name)
            raise

    async def remove_user(self, user_name, logger, retries=3):
        async with self.lock:
            attempt = 0
            while True:
                if attempt > 0:
                    await self.refresh(logger=logger)
                if user_name not in self.users:
                    return
                try:
                    definition = await Operator.custom_objects_api.replace_cluster_custom_object(
                        'user.openshift.io', 'v1', 'groups', self.name,
                        {
                            "apiVersion": "user.openshift.io/v1",
                            "kind": "Group",
                            "metadata": self.metadata,
                            "users": [name for name in self.users if name != user_name],
                        }
                    )
                    self.__init__(definition)
                    logger.info(f"Removed {user_name} from group {self.name}")
                    return
                except kubernetes_asyncio.client.exceptions.ApiException as e:
                    if e.status == 404:
                        # No group? consider the user removed!
                        Group.unregister(self.name)
                        return
                    if e.status == 409 and attempt < retries:
                        # Conflict, refresh from API and retry
                        attempt += 1
                    else:
                        raise


class Identity:
    @staticmethod
    async def get(name, logger=None, retries=0, retry_delay=1):
        while True:
            try:
                definition = await Operator.custom_objects_api.get_cluster_custom_object(
                    'user.openshift.io', 'v1', 'identities', name
                )
                return Identity(definition)
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if retries > 0:
                    logger.info(f"Retrying get identity {name}")
                    await asyncio.sleep(retry_delay)
                    retries -= 1;
                else:
                    raise

    def __init__(self, definition):
        self.extra = definition.get('extra', {})
        self.metadata = definition['metadata']
        self.provider_name = definition.get('providerName')
        self.provider_user_name = definition.get('providerUserName')
        self.user = definition.get('user')

    def __str__(self):
        return f"Identity {self.name}"

    @property
    def email(self):
        return self.extra.get('email')

    @property
    def name(self):
        return self.metadata['name']

    @property
    def providerName(self):
        return self.provider_name

    @property
    def providerUserName(self):
        return self.provider_user_name

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
    @staticmethod
    async def get(name):
        definition = await Operator.custom_objects_api.get_cluster_custom_object(
            'user.openshift.io', 'v1', 'users', name
        )
        return User(definition)

    def __init__(self, definition):
        self.identities = definition.get('identities')
        self.metadata = definition['metadata']

    def __str__(self):
        return f"User {self.name}"

    @property
    def creation_datetime(self):
        return datetime.strptime(
            self.creation_timestamp, '%Y-%m-%dT%H:%M:%SZ'
        ).replace(tzinfo = timezone.utc)

    @property
    def creation_timestamp(self):
        return self.metadata['creationTimestamp']

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

    async def cleanup_on_delete(self, logger):
        user_group_member_list = await Operator.custom_objects_api.list_cluster_custom_object(
            operator_domain, operator_version, 'usergroupmembers',
            label_selector = f"usergroup.pfe.redhat.com/user-uid={self.uid}",
        )
        for user_group_member_definition in user_group_member_list.get('items', []):
            user_group_member_name = user_group_member_definition['metadata']['name']
            logger.info(f"Cleanup UserGroupMember {user_group_member_name} for deleted user {self.name}")
            await Operator.custom_objects_api.delete_cluster_custom_object(
                operator_domain, operator_version, 'usergroupmembers', user_group_member_name
            )

    async def get_identities(self, logger, retries=0, retry_delay=1):
        if not self.identities:
            return []
        identities = []
        for identity_name in self.identities:
            identities.append(await Identity.get(identity_name, retries=6, retry_delay=0.5, logger=logger))
        return identities

    async def manage_groups(self, logger):
        for config in UserGroupConfig.list():
            await config.manage_user_group_members(self, logger)


class UserGroupConfig:
    __configs = {}

    @staticmethod
    def get(name):
        return UserGroupConfig.__configs.get(name)

    @staticmethod
    def list():
        return UserGroupConfig.__configs.values()

    @staticmethod
    async def preload():
        # Preload all UserGroupConfig definitions
        user_group_configs_list = await Operator.custom_objects_api.list_cluster_custom_object(
            operator_domain, operator_version, 'usergroupconfigs'
        )

        for definition in user_group_configs_list.get('items', []):
            UserGroupConfig.register(
                name = definition['metadata']['name'],
                spec = definition['spec'],
            )

    @staticmethod
    def register(name, **kwargs):
        config = UserGroupConfig.get(name)
        if config:
            config.__init__(name=name, **kwargs)
        else:
            config = UserGroupConfig(name=name, **kwargs)
            UserGroupConfig.__configs[name] = config
        return config

    def __init__(self, name, spec):
        self.name = name
        self.spec = spec
        self.api = [
            UserGroupConfigAPI(item) for item in spec['api']
        ] if 'api' in self.spec else []
        self.ldap = [
            UserGroupConfigLDAP(item) for item in spec['ldap']
        ] if 'ldap' in self.spec else []
        self.salesforce = [
            UserGroupConfigSalesforce(item) for item in spec['salesforce']
        ] if 'salesforce' in self.spec else []
        self._lock = asyncio.Lock()

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
        """
        Interval to recheck user group memberships to detect changes in seconds.
        Default 3 hours.
        """
        return int(self.spec.get('refreshInterval', 3 * 60 * 60))

    async def cleanup_on_delete(self, logger):
        _continue = None
        user_group_member_names = []
        while True:
            user_group_member_list = await Operator.custom_objects_api.list_cluster_custom_object(
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
            user_group_member_list = await Operator.custom_objects_api.delete_cluster_custom_object(
                operator_domain, operator_version, 'usergroupmembers', user_group_member_name
            )

    async def manage_user_group_members(self, user, logger):
        logger.info(f"Managing user {user.name}")
        group_names = set()

        for identity in await user.get_identities(logger=logger):
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

            for api in self.api:
                if not api.identity_provider_name \
                or api.identity_provider_name == identity.provider_name:
                    identity_group_names.update(
                        await api.get_group_names(user, identity, logger)
                    )

            for ldap in self.ldap:
                if not ldap.identity_provider_name \
                or ldap.identity_provider_name == identity.provider_name:
                    identity_group_names.update(
                        await ldap.get_group_names(user, identity, logger)
                    )

            for salesforce in self.salesforce:
                if not salesforce.identity_provider_name \
                or salesforce.identity_provider_name == identity.provider_name:
                    identity_group_names.update(
                        await salesforce.get_group_names(user, identity, logger)
                    )

            for group_name in identity_group_names:
                await UserGroupMember.create(
                    config = self,
                    group_name = group_name,
                    identity = identity,
                    logger = logger,
                    user = user,
                )

            group_names.update(identity_group_names)

        user_group_member_list = await Operator.custom_objects_api.list_cluster_custom_object(
            operator_domain, operator_version, 'usergroupmembers',
            label_selector = f"usergroup.pfe.redhat.com/config={self.name},usergroup.pfe.redhat.com/user-uid={user.uid}",
        )
        for user_group_member_definition in user_group_member_list.get('items', []):
            name = user_group_member_definition['metadata']['name']
            group_name = user_group_member_definition['spec']['group']['name']
            if group_name not in group_names:
                logger.info(f"Cleanup UserGroupMember {name}")
                await Operator.custom_objects_api.delete_cluster_custom_object(
                    operator_domain, operator_version, 'usergroupmembers', name
                )

    async def manage_groups(self, logger):
        async with self._lock:
            await self._manage_groups(logger=logger)


    async def _manage_groups(self, logger):
        _continue = None
        last_processed_user_name = None
        while True:
            try:
                user_list = await Operator.custom_objects_api.list_cluster_custom_object(
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
                    await self.manage_user_group_members(user, logger)
                _continue = user_list['metadata'].get('continue')
                if not _continue:
                    break
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 410:
                    # Query expired before completion, reset.
                    logger.info("Restarting user list for group management")
                    _continue = None
                else:
                    raise

    def unregister(self):
        return UserGroupConfig.__configs.pop(self.name)


class UserGroupConfigAPI:
    def __init__(self, definition):
        self.group_mappings = [
            UserGroupConfigAPIGroupMapping(item) for item in definition.get('groupMappings', [])
        ]
        self.auth = UserGroupConfigAPIAuth(definition['authSecret'])
        self.identity_provider_name = definition.get('identityProviderName')
        self.lock = asyncio.Lock()
        request = definition.get('request', {})
        self.request_json_data = request.get('jsonData')
        self.request_method = request.get('method', 'GET')
        self.url = definition['url']
        self.when = definition.get('when')

    async def get_api_response(self, user, identity, logger, retries=5):
        async with self.lock:
            attempt = 0
            access_token = await self.auth.get_access_token(logger=logger)
            headers = {"cache-control": "no-cache"}
            headers['Authorization'] = f"Bearer {access_token}"
            jinja_vars = {"user": user, "identity": identity}
            url = jinja2process(self.url, variables=jinja_vars)

            while True:
                try:
                    async with aiohttp.ClientSession() as session:
                        if self.request_method == 'POST':
                            json_data = {
                                key: jinja2process(value, variables=jinja_vars)
                                for key, value in self.request_json_data.items()
                            }
                            async with session.post(url, headers=headers, json=json_data) as response:
                                return await response.json()
                        async with session.get(url, headers=headers) as response:
                            return await response.json()
                except Exception as exception:
                    if attempt < retries:
                        logger.warning(f"API error: {exception}")
                        attempt += 1
                        await asyncio.sleep(5)
                    else:
                        raise

    async def get_group_names(self, user, identity, logger):
        group_names = set()
        jinja_vars = {"user": user, "identity": identity}
        if (
            self.when and
            not check_condition(self.when, variables=jinja_vars)
        ):
            return group_names

        api_response = await self.get_api_response(user=user, identity=identity, logger=logger)
        for group_mapping in self.group_mappings:
            src = jmespath.search(group_mapping.jmes_path, api_response)
            if src is None:
                continue
            if not isinstance(src, list):
                src = [src]
            for value in src:
                if group_mapping.value_to_group:
                    for value_to_group in group_mapping.value_to_group:
                        if value == value_to_group.value:
                            group_names.update(value_to_group.get_groups(value))
                else:
                    group_names.add(value)
        return group_names


class UserGroupConfigAPIGroupMapping:
    def __init__(self, definition):
        self.jmes_path = definition['jmesPath']
        self.value_to_group = [
            UserGroupConfigAPIGroupMappingValueToGroup(item) for item in definition['valueToGroup']
        ] if 'valueToGroup' in definition else None


class UserGroupConfigAPIGroupMappingValueToGroup:
    def __init__(self, definition):
        self.group = definition.get('group')
        self.groups = definition.get('groups')
        self.value = definition.get('value')

    def get_groups(self, default_group_name):
        if self.group is None and self.groups is None:
            return default_group_name
        else:
            return (self.groups or []) + ([self.group] if self.group else [])


class UserGroupConfigAPIAccessToken:
    @classmethod
    async def load_or_new(cls, name: str, namespace: str):
        access_token = cls(name=name, namespace=namespace)
        try:
            await access_token._read_secret()
        except kubernetes_asyncio.client.exceptions.ApiException as err:
            if err.status != 404:
                raise
        return access_token

    def __init__(self, name: str, namespace: str):
        self.name = name
        self.namespace = namespace
        self.auth_checksum = None
        self.is_loaded = False

    def __str__(self):
        return f"UserGroupConfigAPIAccessToken {self.name}"

    @property
    def expires_in(self):
        return int(self._data.get('expires_in', 60))

    @property
    def is_expired(self):
        """Consider token expired if it expires within 10 seconds."""
        return time() > self.issued_at + self.expires_in - 10

    @property
    def issued_at(self):
        return int(self._data.get('issued_at', self.updated_at))

    @property
    def value(self) -> str:
        return self._data['access_token']

    async def _read_secret(self):
        '''
        Attempt to read API access token secret.
        '''
        secret = await Operator.core_v1_api.read_namespaced_secret(self.name, self.namespace)
        self.auth_checksum = b64decode(secret.data['auth_checksum']).decode('utf-8')
        self._data = json.loads(b64decode(secret.data['data']).decode('utf-8'))
        self.is_loaded = True
        self.updated_at = int(secret.metadata.annotations[f"{operator_domain}/updated-at"])

    async def refresh(self, client_id: str, client_secret: str) -> bool:
        refresh_token = self._data.get('refresh_token')
        instance_url = self._data.get('instance_url')
        if refresh_token is None or instance_url is None:
            return

        headers = {"cache-control": "no-cache"}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{instance_url}/services/oauth2/token",
                headers=headers,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,

                }
            ) as response:
                if response.status not in {200, 201}:
                    text = await response.text()
                    raise kopf.TemporaryError(
                        f"Failed to refresh access token for {self}: {text}"
                    )
                data = await response.json()
                await self._access_token.update(
                    auth_checksum=self._checksum,
                    data=data,
                )

    async def update(self, auth_checksum, data) -> None:
        self._data = data
        secret_data = {
            "auth_checksum": b64encode(auth_checksum.encode('utf-8')).decode('utf-8'),
            "data": b64encode(json.dumps(self._data).encode('utf-8')).decode('utf-8'),
        }
        try:
            await Operator.core_v1_api.patch_namespaced_secret(
                name=self.name,
                namespace=self.namespace,
                body={
                    "data": secret_data,
                    "metadata": {
                        "annotations": {
                            f"{operator_domain}/updated-at": str(int(time())),
                        }
                    }
                }
            )
            return
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 404:
                raise
        await Operator.core_v1_api.create_namespaced_secret(
            namespace=self.namespace,
            body=kubernetes_asyncio.client.V1Secret(
                data=secret_data,
                metadata=kubernetes_asyncio.client.V1ObjectMeta(
                    name=self.name,
                    annotations={
                        f"{operator_domain}/updated-at": str(int(time())),
                    }
                )
            )
        )

class UserGroupConfigAPIAuth:
    def __init__(self, definition):
        self.name = definition['name']
        self.namespace = definition.get('namespace', Operator.operator_namespace)
        self._auth_secret = None
        self._access_token = None
        self._checksum = None
        self._parameters = None
        self._type = None
        self._url = None

    def __str__(self):
        return f"UserGroupConfigAPIAuth {self.name}"

    @property
    def client_id(self):
        return self._parameters.get('client_id')

    @property
    def client_secret(self):
        return self._parameters.get('client_secret')

    async def _read_secret(self):
        '''
        Attempt to read API auth secret with retries in case the configuration was created before the secret.
        '''
        attempt = 0
        while True:
            try:
                secret = await Operator.core_v1_api.read_namespaced_secret(self.name, self.namespace)
                self._checksum = sha256(json.dumps(secret.data, sort_keys=True).encode('utf-8')).hexdigest()
                if 'type' not in secret.data:
                    raise kopf.TemporaryError(
                        f"Auth secret {self.name} in {self.namespace} does not have data.type",
                        delay=600
                    )
                self._type = b64decode(secret.data['type']).decode('utf-8')
                if self._type == 'jwt':
                    if 'url' not in secret.data:
                        raise kopf.TemporaryError(
                            f"JWT auth secret does not specify data.url",
                            delay=600
                        )
                    self._url = b64decode(secret.data['url']).decode('utf-8')
                    if 'parameters' not in secret.data:
                        raise kopf.TemporaryError(
                            f"JWT auth secret does not specify data.parameters",
                            delay=600
                        )
                    self._parameters = yaml.safe_load(b64decode(secret.data['parameters']).decode('utf-8'))
                    return
                raise kopf.TemporaryError(
                    f"Unknown auth type '{self.type}' from auth ecret {self.name} in {self.namespace}",
                    delay=600
                )
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404 and attempt < 10:
                    attempt += 1
                    await asyncio.sleep(0.5)
                else:
                    raise

    async def get_access_token(self, logger):
        if (
            self._access_token is not None and
            self._access_token.is_loaded and
            not self._access_token.is_expired
        ):
            return self._access_token.value

        await self._read_secret()

        if self._access_token is None:
            self._access_token = await UserGroupConfigAPIAccessToken.load_or_new(
                name=f"{self.name}-access-token",
                namespace=self.namespace,
            )

        if (
            self._access_token.is_loaded and
            self._access_token.auth_checksum == self._checksum
        ):
            if not self._access_token.is_expired:
                return self._access_token.value
            if await self._access_token.refresh(
                client_id=self.client_id,
                client_secret=self.client_secret,
            ):
                return self._access_token.value

        headers = {"cache-control": "no-cache"}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self._url,
                headers=headers,
                data=self._parameters
            ) as response:
                if response.status not in {200, 201}:
                    text = await response.text()
                    raise kopf.TemporaryError(
                        f"Failed to get access token for {self}: {text}"
                    )
                data = await response.json()
                await self._access_token.update(
                    auth_checksum=self._checksum,
                    data=data,
                )
                return self._access_token.value


    async def get_parameters(self):
        await self._read_secret()
        return self._parameters

    async def get_type(self):
        await self._read_secret()
        return self._type

    async def get_url(self):
        await self._read_secret()
        return self._url


class UserGroupConfigLDAP:
    ldapUrlRegex = re.compile(r'^(ldaps?)://([^:]+)(?::(\d+))?$')

    def __init__(self, definition):
        self.attribute_to_group = [
            UserGroupConfigLDAPAttributeToGroup(item) for item in definition['attributeToGroup']
        ] if 'attributeToGroup' in definition else None
        self.auth_secret = UserGroupConfigLDAPAuthSecret(definition['authSecret'])
        self.ca_cert = definition.get('caCert')
        self.connection = None
        self.identity_provider_name = definition.get('identityProviderName')
        self.insecure = definition.get('insecure', False)
        self.lock = asyncio.Lock()
        self.url = definition['url']
        self.user_base_dn = definition['userBaseDN']
        self.user_object_class = definition.get('userObjectClass', 'inetOrgPerson')
        self.user_search_attribute = definition.get('userSearchAttribute', 'uid')
        self.user_search_value = definition.get('userSearchValue', 'name')

    @property
    def ca_cert_file(self):
        if not self.ca_cert:
            return None
        file_path = os.path.join('/tmp', sha256(self.ca_cert.encode('utf-8')).hexdigest())
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(self.ca_cert)
        return file_path

    async def connect(self):
        bind_dn = await self.get_bind_dn()
        bind_password = await self.get_bind_password()
        if self.connection:
            return self.connection
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, self.__noasync_ldap_connect,
                bind_dn, bind_password,
            )
            return self.connection

    async def get_bind_dn(self):
        return await self.auth_secret.get_bind_dn()

    async def get_bind_password(self):
        return await self.auth_secret.get_bind_password()

    async def get_group_names(self, user, identity, logger, retries=5):
        async with self.lock:
            attempt = 0
            while True:
                try:
                    await self.connect()
                    loop = asyncio.get_event_loop()
                    return await loop.run_in_executor(
                        None, self.__noasync_get_group_names,
                        user, identity, logger
                    )
                except ldap3.core.exceptions.LDAPCommunicationError:
                    if attempt < retries:
                        logger.warning("LDAP connection failed, will retry")
                        attempt += 1
                        await asyncio.sleep(5)
                        self.connection = None
                    else:
                        raise

    def __noasync_get_group_names(self, user, identity, logger):
        # ldap3 does not support asyncio
        group_names = set()

        # If restricted to an identity provider then check match
        if self.identity_provider_name \
        and self.identity_provider_name != identity.provider_name:
            return group_names

        search_value = user.name if self.user_search_value == 'name' else identity.extra.get(self.user_search_value)
        if not search_value:
            return group_names

        user_object_def = ldap3.ObjectDef(self.user_object_class, self.connection)
        if not hasattr(user_object_def, self.user_search_attribute):
            user_object_def += self.user_search_attribute
        if self.attribute_to_group:
            for attribute in self.attribute_to_group:
                if not hasattr(user_object_def, attribute.attribute):
                    user_object_def += attribute.attribute

        reader = ldap3.Reader(
            self.connection, user_object_def, self.user_base_dn,
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
                logger.warn("%s has no attribute %s", attribute.attribute, ldap_user.entry_dn)

        return group_names

    def __noasync_ldap_connect(self, bind_dn, bind_password):
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
                version = ssl.PROTOCOL_TLSv1_2,
            ),
            use_ssl = protocol == 'ldaps',
        )

        self.connection = ldap3.Connection(server, bind_dn, bind_password)

        if protocol == 'ldap' and not self.insecure:
            self.connection.start_tls()

        self.connection.bind()


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
        if self.group is None and self.groups is None:
            return default_group_name
        return (self.groups or []) + ([self.group] if self.group else [])


class UserGroupConfigLDAPAuthSecret:
    def __init__(self, definition):
        self.name = definition['name']
        self._bind_dn = None
        self._bind_password = None
        self._lock = asyncio.Lock()
        self.namespace = definition.get('namespace', Operator.operator_namespace)

    async def _read_secret(self):
        '''
        Attempt to read LDAP secret with retries in case the configuration was created before the secret.
        '''
        attempt = 0
        while True:
            try:
                secret = await Operator.core_v1_api.read_namespaced_secret(self.name, self.namespace)
                self._bind_dn = b64decode(secret.data['bindDN']).decode('utf-8')
                self._bind_password = b64decode(secret.data['bindPassword']).decode('utf-8')
                return
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404 and attempt < 10:
                    attempt += 1
                    await asyncio.sleep(0.5)
                else:
                    raise

    async def get_bind_dn(self):
        if self._bind_dn:
            return self._bind_dn
        async with self._lock:
            if not self._bind_dn:
                await self._read_secret()
        return self._bind_dn

    async def get_bind_password(self):
        if self._bind_password:
            return self._bind_password
        async with self._lock:
            if not self._bind_password:
                await self._read_secret()
            return self._bind_password


class UserGroupConfigSalesforce:
    def __init__(self, definition):
        self.consumer_key = definition['consumerKey']
        self.consumer_secret = UserGroupConfigSalesforceConsumerSecret(definition['consumerSecret'])
        self.field_to_group = [
            UserGroupConfigSalesforceFieldToGroup(item) for item in definition['fieldToGroup']
        ] if 'fieldToGroup' in definition else None
        self.identity_provider_name = definition.get('identityProviderName')
        self.lock = asyncio.Lock()
        self.url = definition.get('url', 'https://login.salesforce.com')
        self.user_search_field = definition.get('userSearchField', 'federationId')
        self.user_search_value = definition.get('userSearchValue', 'name')
        self.username = definition['username']


    async def get_group_names(self, user, identity, logger):
        async with self.lock:
            salesforce_api = await self.salesforce_api()
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self.__noasync_get_group_names,
                user, identity, logger, salesforce_api, logger
            )

    def __noasync_get_group_names(self, user, identity, salesforce_api, logger):
        # simple_salesforce does not support asyncio
        group_names = set()

        # If restricted to an identity provider then check match
        if self.identity_provider_name \
        and self.identity_provider_name != identity.provider_name:
            return group_names

        search_value = user.name if self.user_search_value == 'name' else identity.extra.get(self.user_search_value)
        if not search_value:
            return group_names

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

    async def salesforce_api(self):
        return simple_salesforce.Salesforce(
            instance_url = self.url,
            username = self.username,
            consumer_key = self.consumer_key,
            privatekey_file = await self.consumer_secret.get_file_path(),
        )


class UserGroupConfigSalesforceConsumerSecret:
    def __init__(self, definition):
        self.name = definition['name']
        self._tempfile = None
        self._lock = asyncio.Lock()
        self.namespace = definition.get('namespace', Operator.operator_namespace)

    def __del__(self):
        if self._tempfile:
            os.unlink(self._tempfile.name)

    async def get_file_path(self):
        if self._tempfile:
            return self._tempfile.name
        async with self._lock:
            if not self._tempfile:
                await self._read_secret_to_tempfile()
        return self._tempfile.name

    async def _read_secret_to_tempfile(self):
        '''
        Attempt to read Salesforce client secret with retries in case the configuration was created before the secret.
        '''
        attempt = 0
        while True:
            try:
                secret = await Operator.core_v1_api.read_namespaced_secret(self.name, self.namespace)
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
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404 and attempt < 10:
                    attempt += 1
                    await asyncio.sleep(0.5)
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
        if self.group is None and self.groups is None:
            return default_group_name
        return (self.groups or []) + ([self.group] if self.group else [])


class UserGroupMember:
    @staticmethod
    async def create(config, group_name, identity, logger, user):
        group = await Group.get(group_name, init_new=True)
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
                    "group": group.ref,
                    "identity": identity.ref,
                    "user": user.ref,
                }
            }
            if group:
                definition['metadata']['labels']['usergroup.pfe.redhat.com/group-uid'] = group.uid
            await Operator.custom_objects_api.create_cluster_custom_object('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', definition)
            logger.info(f"Created UserGroupMember {name}")
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

    def __init__(self, definition):
        self.metadata = definition['metadata']
        self.spec = definition['spec']

    @property
    def group_name(self):
        return self.spec['group']['name']


@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
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

    await Operator.on_startup()


@kopf.on.event('user.openshift.io', 'v1', 'groups')
async def group_handler(event, **_):
    if event['type'] == 'DELETED':
        await Group.unregister(event['object']['metadata']['name'])
    else:
        await Group.register(event['object'])


@kopf.on.event('user.openshift.io', 'v1', 'users')
async def user_handler(event, logger, **_):
    user = User(event['object'])
    if event['type'] == 'DELETED':
        await user.cleanup_on_delete(logger=logger)
    else:
        await user.manage_groups(logger=logger)


@kopf.on.event('oauth.openshift.io', 'v1', 'oauthaccesstokens')
async def oauthaccesstoken_handler(event, logger, **_):
    # Do not begin updating from oauthaccesstokens initially.
    # User updates will already be proccessed by the user handler.
    if datetime.now(timezone.utc) - operator_start_datetime < timedelta(minutes=5):
        return
    # Only manage groups for user when OAuthAccessTokens is added and user is not recently created.
    if event['type'] != 'ADDED':
        user = await User.get(event['object']['userName'])
        if datetime.now(timezone.utc) - user.creation_datetime > timedelta(minutes=1):
            await user.manage_groups(logger=logger)


@kopf.on.create('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs', id='usergroupconfig_create')
@kopf.on.update('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs', id='usergroupconfig_update')
async def usergroupconfig_create_or_update(name, spec, logger, **_):
    config = UserGroupConfig.register(name=name, spec=spec)
    await config.manage_groups(logger=logger)

@kopf.on.resume('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs')
async def usergroupconfig_resume(name, spec, **_):
    UserGroupConfig.register(name=name, spec=spec)

@kopf.daemon('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs', cancellation_timeout=1)
async def usergroupconfig_daemon(stopped, name, spec, logger, **_):
    config = UserGroupConfig.register(name=name, spec=spec)
    try:
        while True:
            await asyncio.sleep(config.refresh_interval)
            if stopped:
                break
            await config.manage_groups(logger=logger)
    except asyncio.CancelledError:
        pass

@kopf.on.delete('usergroup.pfe.redhat.com', 'v1', 'usergroupconfigs')
async def usergroupconfig_delete(name, spec, logger, **_):
    config = UserGroupConfig(name=name, spec=spec)
    await config.cleanup_on_delete(logger)
    config.unregister()


@kopf.on.create('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', id='usergroupmember_create')
@kopf.on.resume('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', id='usergroupmember_resume')
@kopf.on.update('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers', id='usergroupmember_update')
async def usergroupmember_event(spec, logger, **_):
    group = await Group.get(spec['group']['name'], init_new=True)
    await group.add_user(spec['user']['name'], logger=logger)

@kopf.on.delete('usergroup.pfe.redhat.com', 'v1', 'usergroupmembers')
async def usergroupmember_delete(spec, logger, **_):
    try:
        group = await Group.get(spec['group']['name'])
        await group.remove_user(spec['user']['name'], logger=logger)
    except kubernetes_asyncio.client.exceptions.ApiException as e:
        if e.status != 404:
            raise
