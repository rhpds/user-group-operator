import importlib.util
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'operator'))
module_spec = importlib.util.spec_from_file_location('user_group_operator', ROOT / 'operator/operator.py')
operator = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(operator)
LOGGER = logging.getLogger(__name__)


class LoginRefreshTests(unittest.IsolatedAsyncioTestCase):
    async def check_event(self, event_type, expected, startup_age=10, user_age=10):
        now = datetime.now(timezone.utc)
        user = SimpleNamespace(
            creation_datetime=now - timedelta(minutes=user_age),
            manage_groups=AsyncMock(),
        )
        with patch.object(operator, 'operator_start_datetime', now - timedelta(minutes=startup_age)), \
             patch.object(operator.User, 'get', AsyncMock(return_value=user)) as get_user:
            await operator.oauthaccesstoken_handler(
                {'type': event_type, 'object': {'userName': 'alice'}}, LOGGER
            )
        self.assertEqual(user.manage_groups.await_count, expected)
        if expected:
            get_user.assert_awaited_once_with('alice')

    async def test_new_login_refreshes_existing_user(self):
        await self.check_event('ADDED', 1)

    async def test_other_token_events_do_not_refresh(self):
        for event_type in ('MODIFIED', 'DELETED', None):
            with self.subTest(event_type=event_type):
                await self.check_event(event_type, 0)

    async def test_startup_guard_is_preserved(self):
        await self.check_event('ADDED', 0, startup_age=1)

    async def test_new_user_guard_is_preserved(self):
        await self.check_event('ADDED', 0, user_age=0)


class MembershipRepairTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        operator.Group.instances.clear()
        self.api = SimpleNamespace(
            create_cluster_custom_object=AsyncMock(side_effect=operator.kubernetes_asyncio.client.exceptions.ApiException(status=409)),
            replace_cluster_custom_object=AsyncMock(),
        )
        self.api_patch = patch.object(operator.Operator, 'custom_objects_api', self.api)
        self.api_patch.start()
        self.addCleanup(self.api_patch.stop)
        self.addCleanup(operator.Group.instances.clear)
        self.user = operator.User({'metadata': {'name': 'alice', 'uid': 'alice-uid'}})
        self.identity = operator.Identity({'metadata': {'name': 'sso:alice', 'uid': 'identity-uid'}})

    async def reconcile(self):
        await operator.UserGroupMember.create(
            SimpleNamespace(name='cluster'), 'rover-team', self.identity, LOGGER, self.user
        )

    async def test_existing_record_repairs_missing_group_member(self):
        definition = {'metadata': {'name': 'rover-team', 'uid': 'group-uid', 'resourceVersion': '2'}, 'users': ['bob']}
        await operator.Group.register(definition)
        self.api.replace_cluster_custom_object.return_value = {
            **definition, 'users': ['bob', 'alice']
        }
        await self.reconcile()
        self.api.replace_cluster_custom_object.assert_awaited_once()
        body = self.api.replace_cluster_custom_object.call_args.args[-1]
        self.assertEqual(body['users'], ['bob', 'alice'])

    async def test_existing_member_does_not_write_group(self):
        await operator.Group.register({'metadata': {'name': 'rover-team', 'uid': 'group-uid'}, 'users': ['alice']})
        await self.reconcile()
        self.api.replace_cluster_custom_object.assert_not_awaited()

    async def test_non_conflict_error_is_propagated(self):
        await operator.Group.register({'metadata': {'name': 'rover-team', 'uid': 'group-uid'}, 'users': []})
        self.api.create_cluster_custom_object.side_effect = operator.kubernetes_asyncio.client.exceptions.ApiException(status=403)
        with self.assertRaises(operator.kubernetes_asyncio.client.exceptions.ApiException):
            await self.reconcile()
        self.api.replace_cluster_custom_object.assert_not_awaited()


class LDAPMappingTests(unittest.TestCase):
    def test_each_mapping_reads_its_own_attribute(self):
        config = operator.UserGroupConfigLDAP({
            'url': 'ldaps://example.com', 'authSecret': {'name': 'ldap'},
            'userBaseDN': 'dc=example,dc=com',
            'attributeToGroup': [
                {'attribute': 'memberOf', 'valueToGroup': [{'value': 'cn=team,dc=example,dc=com', 'group': 'rover-team'}]},
                {'attribute': 'departmentNumber'},
            ],
        })
        entry = {
            'memberOf': SimpleNamespace(values=['cn=team,dc=example,dc=com']),
            'departmentNumber': SimpleNamespace(values=['engineering']),
        }
        reader = MagicMock()
        reader.__len__.return_value = 1
        reader.__getitem__.return_value = entry
        with patch.object(operator.ldap3, 'ObjectDef', return_value=SimpleNamespace(uid=True, memberOf=True, departmentNumber=True)), \
             patch.object(operator.ldap3, 'Reader', return_value=reader):
            groups = config._UserGroupConfigLDAP__noasync_get_group_names(
                SimpleNamespace(name='alice'), SimpleNamespace(provider_name='sso'), LOGGER
            )
        self.assertEqual(groups, {'rover-team', 'ldap-departmentNumber-engineering'})


@unittest.skipUnless(shutil.which('helm'), 'helm is required for chart rendering tests')
class HelmRefreshTests(unittest.TestCase):
    def render_config(self, *settings):
        command = ['helm', 'template', 'test', str(ROOT / 'helm'), '--set', 'config.identityProviderGroups.enable=true']
        for setting in settings:
            command.extend(['--set', setting])
        documents = yaml.safe_load_all(subprocess.check_output(command, text=True))
        return next(doc for doc in documents if doc and doc.get('kind') == 'UserGroupConfig')

    def test_configured_interval_is_rendered(self):
        self.assertEqual(self.render_config('config.refreshInterval=60')['spec']['refreshInterval'], 60)

    def test_omitted_interval_keeps_operator_default(self):
        spec = self.render_config()['spec']
        self.assertNotIn('refreshInterval', spec)
        self.assertEqual(operator.UserGroupConfig('cluster', spec).refresh_interval, 10800)


if __name__ == '__main__':
    unittest.main()
