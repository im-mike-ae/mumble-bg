"""ShitSpeak-facing HTTP endpoints.

A ShitSpeak voice server authenticates pilots by calling *out* to BG at login
(unlike Murmur, where BG registers an Ice authenticator callback that Murmur
calls *into*). This module serves that call.

This is a separate trust domain from the FG->BG control API in
``bg/control.py``: the voice server runs on a different host and holds a
per-server bearer token (``MumbleServer.auth_token``), not the FG rolling-key
control keyring. The endpoint reuses ``bg.authd.service.authenticate``
verbatim, so password/cert/group semantics are identical to the Ice
authenticator path.
"""

import base64
import binascii
import json
import logging
import secrets

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from bg.authd.service import USER_NOT_FOUND
from bg.authd.service import authenticate as authd_authenticate
from bg.authd.service import update_connection_info
from bg.state.models import MumbleServer, MumbleUser

logger = logging.getLogger(__name__)

_HEX_DIGITS = frozenset('0123456789abcdef')


def _auxiliary_data(payload: dict) -> dict:
    """ShitSpeak's authenticator JSON nests connection context under
    ``auxiliary_data``; a plain caller may send the same fields at the top
    level. Merge with the nested values taking precedence."""
    nested = payload.get('auxiliary_data')
    if not isinstance(nested, dict):
        return payload
    merged = dict(payload)
    merged.update(nested)
    return merged


def _normalized_certhash(payload: dict) -> str:
    """Return the client certhash as lowercase hex, or '' if absent.

    ShitSpeak's authenticator JSON carries ``certificate_hash_base64`` (base64
    of the raw 20-byte SHA-1 over the DER leaf certificate), nested under
    ``auxiliary_data``; Murmur — and therefore BG's stored
    ``MumbleUser.certhash`` — uses lowercase hex of the same digest.
    ``certificate_hash_hex`` is also accepted. Raises ValueError on malformed
    input.
    """
    payload = _auxiliary_data(payload)
    b64 = payload.get('certificate_hash_base64')
    if isinstance(b64, str) and b64.strip():
        try:
            raw = base64.b64decode(b64.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError('certificate_hash_base64 is not valid base64') from exc
        return raw.hex()
    hexv = payload.get('certificate_hash_hex')
    if isinstance(hexv, str) and hexv.strip():
        value = hexv.strip().lower()
        if len(value) % 2 or not set(value) <= _HEX_DIGITS:
            raise ValueError('certificate_hash_hex is not valid hex')
        return value
    return ''


def _resolve_server(request, payload: dict) -> MumbleServer | None:
    """Resolve the target server row from ``server_id`` (pk) or ``server_key``.

    Both may arrive in the JSON body *or* in the query string. The query string
    is the important one: ShitSpeak's authenticator JSON schema is fixed
    (``username`` / ``password`` / ``auxiliary_data``) and carries no server
    selector, so a ShitSpeak node identifies itself by pointing
    ``[authenticator.http] url`` at ``…/shitspeak/authenticate?server_id=<pk>``.
    """
    server_id = payload.get('server_id')
    if isinstance(server_id, bool):
        server_id = None
    if server_id is None:
        raw = (request.GET.get('server_id') or '').strip()
        if raw:
            try:
                server_id = int(raw)
            except ValueError:
                return None
    if isinstance(server_id, int):
        return MumbleServer.objects.filter(pk=server_id, is_active=True).first()

    server_key = payload.get('server_key')
    if not (isinstance(server_key, str) and server_key.strip()):
        server_key = request.GET.get('server_key')
    if isinstance(server_key, str) and server_key.strip():
        wanted = server_key.strip()
        for candidate in MumbleServer.objects.filter(is_active=True):
            if candidate.server_key == wanted:
                return candidate
    return None


def _bearer_token(request) -> str:
    header = request.headers.get('Authorization', '')
    if header.startswith('Bearer '):
        return header[len('Bearer '):].strip()
    return ''


def _rejected(code: str, reason: str) -> JsonResponse:
    return JsonResponse(
        {'accepted': False, 'rejected': True, 'code': code, 'reason': reason}, status=403
    )


@csrf_exempt
@require_http_methods(['POST'])
def authenticate(request):
    """POST /shitspeak/authenticate — live login check for a ShitSpeak server.

    Called by ShitSpeak's ``[authenticator] backend = "http"``, whose request
    schema is fixed:

        {"username", "password"|null,
         "auxiliary_data": {"certificate_hash_base64"|null, "session_id",
                            "ip_address", "tls_ja4", …}}

    It carries no server selector, so the node identifies itself in the query
    string: point its ``[authenticator.http] url`` at
    ``…/shitspeak/authenticate?server_id=<pk>`` (``server_key`` also works).
    Both selectors and the certhash fields are additionally accepted at the top
    level of the body, for plain (non-ShitSpeak) callers and tests.

    Accept:   200 ``{"user_id", "display_name", "groups", "is_superuser",
                     "auth_method"}`` — ShitSpeak's contract defaults a 200
              without an ``accepted`` field to accepted.
    Reject:   403 ``{"rejected": true, "code": "user_not_found"|"bad_credentials"}``
              — ShitSpeak maps these markers to its NoSuchUser / WrongPassword
              rejections. (A dedicated ShitSpeak server chains no other
              authenticator, so Murmur's "fall-through" is a reject here.)
    """
    try:
        payload = json.loads(request.body.decode('utf-8'))
        if not isinstance(payload, dict):
            raise ValueError('payload must be an object')
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({'error': 'invalid JSON body'}, status=400)

    server = _resolve_server(request, payload)
    if server is None:
        return JsonResponse({'error': 'unknown or inactive server'}, status=404)

    # Per-server bearer token. An empty stored token disables the endpoint —
    # there is no unauthenticated mode.
    if not server.auth_token:
        logger.warning(
            'shitspeak authenticate refused: server %s has no auth_token configured',
            server.pk,
        )
        return JsonResponse(
            {'error': 'authentication endpoint not enabled for this server'}, status=403
        )
    # Compare as bytes: compare_digest raises TypeError on non-ASCII str
    # input, which a hostile caller could otherwise turn into a 500.
    provided = _bearer_token(request)
    if not provided or not secrets.compare_digest(
        provided.encode('utf-8'), server.auth_token.encode('utf-8')
    ):
        return JsonResponse({'error': 'invalid bearer token'}, status=401)
    if server.driver != MumbleServer.DRIVER_SHITSPEAK:
        return JsonResponse({'error': 'server is not shitspeak-driven'}, status=403)

    username = payload.get('username')
    if not isinstance(username, str) or not username.strip():
        return JsonResponse({'error': 'username is required'}, status=400)
    username = username.strip()
    password = payload.get('password')
    if password is not None and not isinstance(password, str):
        return JsonResponse({'error': 'password must be a string'}, status=400)
    try:
        certhash = _normalized_certhash(payload)
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    # Empty password + matching certhash authenticates as 'cert', matching the
    # Ice authenticator's behavior — do not require a password here.
    result = authd_authenticate(username, password or '', server.pk, certhash=certhash)

    if result is USER_NOT_FOUND:
        logger.info(
            'shitspeak authenticate: user_not_found username=%r server=%s', username, server.pk
        )
        return _rejected('user_not_found', 'no matching registration for this server')
    if result is None:
        logger.info(
            'shitspeak authenticate: bad_credentials username=%r server=%s', username, server.pk
        )
        return _rejected('bad_credentials', 'invalid password or certificate')

    bg_row_id, auth_user_id, display_name, groups, _pilot_user_id, auth_method = result

    # Persist the presented cert hash (and its derived fake) on the row, the way
    # the Ice authenticator does via update_connection_info — the ShitSpeak path
    # previously skipped this, so certhash/certhash_fake never got recorded for
    # ShitSpeak logins. Best-effort: a persistence failure must not fail auth.
    if certhash:
        try:
            update_connection_info(bg_row_id, certhash)
        except Exception:  # noqa: BLE001
            logger.exception(
                'shitspeak authenticate: failed to persist certhash for bg_row_id=%s', bg_row_id
            )

    is_superuser = bool(
        MumbleUser.objects.filter(pk=bg_row_id)
        .values_list('is_mumble_admin', flat=True)
        .first()
    )
    logger.info(
        'shitspeak authenticate: accepted username=%r server=%s user_id=%s method=%s',
        username,
        server.pk,
        auth_user_id,
        auth_method,
    )
    return JsonResponse(
        {
            # ShitSpeak's authenticator-JSON contract defaults a missing
            # `accepted` to false, so an accept MUST say so explicitly or the
            # node rejects the login as "authenticator failure".
            'accepted': True,
            'user_id': auth_user_id,
            'display_name': display_name,
            'groups': groups,
            'is_superuser': is_superuser,
            'auth_method': auth_method,
        }
    )
