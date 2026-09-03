"""Tests for the ShitSpeak-facing POST /shitspeak/authenticate endpoint."""

import base64
import json
from unittest.mock import patch

import pytest
from django.contrib.auth.models import User
from django.test import Client, TestCase

from bg import shitspeak
from bg.authd.service import USER_NOT_FOUND
from bg.state.models import MumbleServer, MumbleUser

TOKEN = 'test-shitspeak-token'


def _accept_tuple(bg_row_id, user_id=99, display_name='Pilot One', groups=('member',)):
    return (bg_row_id, user_id, display_name, list(groups), 5, 'password')


class ShitSpeakAuthenticateViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='pilot1', password='x')
        self.server = MumbleServer.objects.create(
            name='mumble-beta',
            address='voice-beta.example.com:64738',
            ice_host='',
            ice_port=6502,
            driver=MumbleServer.DRIVER_SHITSPEAK,
            auth_token=TOKEN,
            is_active=True,
        )
        self.ice_server = MumbleServer.objects.create(
            name='Main Fleet Comms',
            address='voice.example.com:64738',
            ice_host='127.0.0.1',
            ice_port=6502,
            auth_token=TOKEN,
            is_active=True,
        )
        self.registration = MumbleUser.objects.create(
            user=self.user,
            server=self.server,
            username='pilot1',
            display_name='Pilot One',
            is_active=True,
            is_mumble_admin=True,
        )

    def _post(self, payload, token=TOKEN):
        headers = {}
        if token is not None:
            headers['HTTP_AUTHORIZATION'] = f'Bearer {token}'
        return self.client.post(
            '/shitspeak/authenticate',
            data=json.dumps(payload),
            content_type='application/json',
            **headers,
        )

    def test_accept_returns_identity_with_superuser_flag(self):
        with patch.object(
            shitspeak,
            'authd_authenticate',
            return_value=_accept_tuple(self.registration.pk),
        ) as stub:
            response = self._post(
                {'username': 'pilot1', 'password': 'pw', 'server_id': self.server.pk}
            )
        assert response.status_code == 200
        body = response.json()
        assert body == {
            # A ShitSpeak node treats a missing `accepted` as a rejection, so
            # the accept path must send it explicitly.
            'accepted': True,
            'user_id': 99,
            'display_name': 'Pilot One',
            'groups': ['member'],
            'is_superuser': True,
            'auth_method': 'password',
        }
        stub.assert_called_once_with('pilot1', 'pw', self.server.pk, certhash='')

    def test_user_not_found_maps_to_403(self):
        with patch.object(shitspeak, 'authd_authenticate', return_value=USER_NOT_FOUND):
            response = self._post({'username': 'ghost', 'server_id': self.server.pk})
        assert response.status_code == 403
        assert response.json()['code'] == 'user_not_found'
        assert response.json()['rejected'] is True
        assert response.json()['accepted'] is False

    def test_bad_credentials_map_to_403(self):
        with patch.object(shitspeak, 'authd_authenticate', return_value=None):
            response = self._post(
                {'username': 'pilot1', 'password': 'wrong', 'server_id': self.server.pk}
            )
        assert response.status_code == 403
        assert response.json()['code'] == 'bad_credentials'

    def test_missing_or_wrong_bearer_token_is_401(self):
        for token in (None, 'nope'):
            response = self._post(
                {'username': 'pilot1', 'server_id': self.server.pk}, token=token
            )
            assert response.status_code == 401, token

    def test_empty_stored_token_disables_endpoint(self):
        self.server.auth_token = ''
        self.server.save(update_fields=['auth_token'])
        response = self._post({'username': 'pilot1', 'server_id': self.server.pk})
        assert response.status_code == 403
        assert 'not enabled' in response.json()['error']

    def test_ice_driver_server_is_refused(self):
        response = self._post({'username': 'pilot1', 'server_id': self.ice_server.pk})
        assert response.status_code == 403
        assert 'not shitspeak-driven' in response.json()['error']

    def test_unknown_or_inactive_server_is_404(self):
        response = self._post({'username': 'pilot1', 'server_id': 424242})
        assert response.status_code == 404
        self.server.is_active = False
        self.server.save(update_fields=['is_active'])
        response = self._post({'username': 'pilot1', 'server_id': self.server.pk})
        assert response.status_code == 404

    def test_server_key_resolution(self):
        with patch.object(
            shitspeak,
            'authd_authenticate',
            return_value=_accept_tuple(self.registration.pk),
        ) as stub:
            response = self._post(
                {'username': 'pilot1', 'password': 'pw', 'server_key': self.server.server_key}
            )
        assert response.status_code == 200
        stub.assert_called_once_with('pilot1', 'pw', self.server.pk, certhash='')

    def test_base64_certhash_is_normalized_to_lowercase_hex(self):
        raw = bytes(range(20))
        expected_hex = raw.hex()
        with patch.object(
            shitspeak,
            'authd_authenticate',
            return_value=_accept_tuple(self.registration.pk),
        ) as stub:
            response = self._post(
                {
                    'username': 'pilot1',
                    'server_id': self.server.pk,
                    'certificate_hash_base64': base64.b64encode(raw).decode(),
                }
            )
        assert response.status_code == 200
        stub.assert_called_once_with('pilot1', '', self.server.pk, certhash=expected_hex)

    def test_shitspeak_native_request_shape(self):
        """The real ShitSpeak `backend = "http"` request: no server selector in
        the body (it lives in the query string) and the certhash nested under
        auxiliary_data."""
        raw = bytes(range(20))
        with patch.object(
            shitspeak,
            'authd_authenticate',
            return_value=_accept_tuple(self.registration.pk),
        ) as stub:
            response = self.client.post(
                f'/shitspeak/authenticate?server_id={self.server.pk}',
                data=json.dumps(
                    {
                        'username': 'pilot1',
                        'password': None,
                        'auxiliary_data': {
                            'certificate_hash_base64': base64.b64encode(raw).decode(),
                            'session_id': 42,
                            'ip_address': '203.0.113.5',
                            'tls_ja4': None,
                        },
                    }
                ),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {TOKEN}',
            )
        assert response.status_code == 200
        stub.assert_called_once_with('pilot1', '', self.server.pk, certhash=raw.hex())

    def test_server_key_in_query_string(self):
        with patch.object(
            shitspeak,
            'authd_authenticate',
            return_value=_accept_tuple(self.registration.pk),
        ):
            response = self.client.post(
                f'/shitspeak/authenticate?server_key={self.server.server_key}',
                data=json.dumps({'username': 'pilot1', 'password': 'pw'}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {TOKEN}',
            )
        assert response.status_code == 200

    def test_bad_server_id_in_query_string_is_404(self):
        response = self.client.post(
            '/shitspeak/authenticate?server_id=not-a-number',
            data=json.dumps({'username': 'pilot1', 'password': 'pw'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {TOKEN}',
        )
        assert response.status_code == 404

    def test_invalid_certhash_is_400(self):
        for payload_extra in (
            {'certificate_hash_base64': '!!!not-base64!!!'},
            {'certificate_hash_hex': 'xyz'},
            {'certificate_hash_hex': 'abc'},  # odd length
        ):
            response = self._post(
                {'username': 'pilot1', 'server_id': self.server.pk, **payload_extra}
            )
            assert response.status_code == 400, payload_extra

    def test_missing_username_is_400(self):
        response = self._post({'server_id': self.server.pk})
        assert response.status_code == 400

    def test_invalid_json_is_400(self):
        response = self.client.post(
            '/shitspeak/authenticate',
            data='not json',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {TOKEN}',
        )
        assert response.status_code == 400

    def test_get_is_rejected(self):
        response = self.client.get('/shitspeak/authenticate')
        assert response.status_code == 405


@pytest.mark.parametrize(
    ('payload', 'expected'),
    [
        ({'certificate_hash_hex': 'AABBCC'}, 'aabbcc'),
        ({'certificate_hash_base64': base64.b64encode(b'\xaa\xbb').decode()}, 'aabb'),
        ({}, ''),
        ({'certificate_hash_base64': '', 'certificate_hash_hex': ''}, ''),
    ],
)
def test_normalized_certhash(payload, expected):
    assert shitspeak._normalized_certhash(payload) == expected
