import collections
import copy
import kopf
import kubernetes
import os
import re
import time

operator_domain = os.environ.get('OPERATOR_DOMAIN', 'usergroup.gpte.redhat.com')
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
        attempt = 0
        while True:
            attempt += 1
            try:
                group = Group.get(group_name)
                if group:
                    if user_name in group.users:
                        return
                    else:
                        custom_objects_api.replace_cluster_custom_object(
                            'user.openshift.io', 'v1', 'groups', group_name,
                            {
                                "apiVersion": "user.openshift.io/v1",
                                "kind": "Group",
                                "metadata": group.metadata,
                                "users": group.users + [user_name],
                            }
                        )
                        logger.info(f"Addded {user_name} to group {group_name}")
                        return
                else:
                    custom_objects_api.create_cluster_custom_object(
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
                    return
            except kubernetes.client.rest.ApiException as e:
                if attempt > 3:
                    raise

    @staticmethod
    def get(group_name):
        try:
            resource = custom_objects_api.get_cluster_custom_object(
                'user.openshift.io', 'v1', 'groups', group_name
            )
            return Group(resource)
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                raise

    @staticmethod
    def get_or_create(group_name):
        attempt = 0
        while True:
            attempt += 1
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
                if attempt > 3:
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

    def __init__(self, resource):
        self.metadata = resource.get('metadata')
        self.users = resource.get('users')

    @property
    def name(self):
        return self.metadata['name']

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
    def get(name):
        if not name:
            return
        try:
            resource = custom_objects_api.get_cluster_custom_object(
                'user.openshift.io', 'v1', 'identities', name
            )
            return Identity(resource)
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                raise

    def __init__(self, resource):
        self.extra = resource.get('extra')
        self.metadata = resource.get('metadata')
        self.providerName = resource.get('providerName')
        self.providerUserName = resource.get('providerUserName')
        self.user = resource.get('user')

    @property
    def email(self):
        if self.extra:
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
    def __init__(self, resource, logger):
        self.identities = resource.get('identities', [])
        self.logger = logger
        self.metadata = resource['metadata']

    @property
    def identity(self):
        if self.identities:
            return self.identities[0]

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

    def manage_groups(self):
        config = UserGroupConfig.get_cluster_config()
        identity = Identity.get(self.identity)
        if not identity:
            return
        if config.identity_provider_groups_enabled:
            UserGroupMember.create(
                self, identity, config.identity_provider_groups_prefix + identity.providerName, self.logger
            )
        if config.email_domain_groups_enabled:
            email = identity.email
            if email and '@' in email:
                domain = email.split('@')[1]
                UserGroupMember.create(
                    self, identity, config.email_domain_groups_prefix + domain, self.logger
                )

class UserGroupConfig:
    __cluster_config = None

    @staticmethod
    def get_cluster_config():
        if UserGroupConfig.__cluster_config == None:
            try:
                resource = custom_objects_api.get_cluster_custom_object(
                    operator_domain, operator_version, 'usergroupconfigs', 'cluster'
                )
                UserGroupConfig.__cluster_config = UserGroupConfig(resource)
            except kubernetes.client.rest.ApiException as e:
                if e.status != 404:
                    raise
        return UserGroupConfig.__cluster_config

    @staticmethod
    def set_cluster_config(resource):
        if UserGroupConfig.__cluster_config == None:
            UserGroupConfig.__cluster_config = UserGroupConfig(resource)
        else:
            UserGroupConfig.__cluster_config.__init__(resource)

    def __init__(self, resource):
        self.metadata = resource['metadata']
        self.spec = resource['spec']

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

class UserGroupMember:
    @staticmethod
    def create(user, identity, group_name, logger):
        group = Group.get_or_create(group_name)
        name = f"{user.name}.{group_name}"
        try:
            custom_objects_api.create_cluster_custom_object(
                'usergroup.gpte.redhat.com', 'v1', 'usergroupmembers',
                {
                    "apiVersion": "usergroup.gpte.redhat.com/v1",
                    "kind": "UserGroupMember",
                    "metadata": {
                        "name": name,
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
            )
            logger.info(f"Created UserGroupMember {name}")
        except kubernetes.client.rest.ApiException as e:
            if e.status != 409:
                raise

    def __init__(self, resource):
        self.metadata = resource['metadata']
        self.spec = resource['spec']

    @property
    def group_name(self):
        return self.spec['group']['name']

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    # Disable scanning for CustomResourceDefinitions updates
    settings.scanning.disabled = True

@kopf.on.event('user.openshift.io', 'v1', 'users')
def user_handler(event, logger, **_):
    if event['type'] in ['ADDED', 'MODIFIED', None]:
        user = User(event['object'], logger)
        user.manage_groups()

@kopf.on.event('usergroup.gpte.redhat.com', 'v1', 'usergroupconfigs')
def config_handler(event, logger, **_):
    if event['type'] in ['ADDED', 'MODIFIED', None]:
        resource = event['object']
        if resource['metadata']['name'] == 'cluster':
            UserGroupConfig.set_cluster_config(resource)

@kopf.on.create('usergroup.gpte.redhat.com', 'v1', 'usergroupmembers')
@kopf.on.resume('usergroup.gpte.redhat.com', 'v1', 'usergroupmembers')
@kopf.on.update('usergroup.gpte.redhat.com', 'v1', 'usergroupmembers')
def usergroupmember_event(spec, logger, **_):
    Group.add_user(
        spec['group']['name'],
        spec['user']['name'],
        logger,
    )

@kopf.on.delete('usergroup.gpte.redhat.com', 'v1', 'usergroupmembers')
def usergroupmember_delete(spec, logger, **_):
    Group.remove_user(
        spec['group']['name'],
        spec['user']['name'],
        logger,
    )
