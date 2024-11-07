from dataclasses import asdict
from enum import Enum
from urllib.parse import parse_qs, urlparse

from flask import Blueprint, redirect, request, url_for

from odp.config import config
from odp.const import ODPScope
from odp.identity import hydra_admin_api
from odp.identity.views import encode_token
from odp.lib import exceptions as x
from odp.lib.auth import get_user_info, get_user_permissions

bp = Blueprint('hydra', __name__)


class LoginMode(Enum):
    LOGIN = 'login'
    SIGNUP = 'signup'

    @classmethod
    def from_login_request(cls, login_request):
        url = login_request['request_url']
        try:
            return LoginMode(parse_qs(urlparse(url).query).get('mode', [])[0])
        except (IndexError, ValueError):
            return LoginMode.LOGIN


class Brand(Enum):
    SAEON = 'saeon'
    NCCRD = 'nccrd'
    SADCO = 'sadco'

    @classmethod
    def from_login_request(cls, login_request):
        client_id = login_request['client']['client_id']
        if client_id == config.ODP.IDENTITY.NCCRD_CLIENT_ID:
            return Brand.NCCRD

        if client_id == config.ODP.IDENTITY.SADCO_CLIENT_ID:
            return Brand.SADCO

        return Brand.SAEON


@bp.route('/login')
def login():
    """
    Implements the login provider component of the Hydra login workflow.
    Hydra redirects to this endpoint based on the ``URLS_LOGIN`` environment
    variable configured on the Hydra server.
    """
    challenge = request.args.get('login_challenge')
    login_request = hydra_admin_api.get_login_request(challenge)
    mode = LoginMode.from_login_request(login_request)
    brand = Brand.from_login_request(login_request).value

    if mode == LoginMode.LOGIN:
        target_endpoint = 'login.login'
    elif mode == LoginMode.SIGNUP:
        target_endpoint = 'signup.signup'
    else:
        raise ValueError

    token = encode_token('login', challenge, brand)
    redirect_to = url_for(target_endpoint, token=token)
    return redirect(redirect_to)


@bp.route('/consent')
def consent():
    """
    Implements the consent provider component of the Hydra consent workflow.
    Hydra redirects to this endpoint based on the ``URLS_CONSENT`` environment
    variable configured on the Hydra server.
    """
    challenge = request.args.get('consent_challenge')
    consent_request = hydra_admin_api.get_consent_request(challenge)
    user_id = consent_request['subject']
    client_id = consent_request['client']['client_id']
    try:
        user_permissions = get_user_permissions(user_id, client_id)
        user_info = get_user_info(user_id, client_id)

        redirect_to = hydra_admin_api.accept_consent_request(
            challenge,
            authorized_scope_ids=[
                requested_scope_id
                for requested_scope_id in consent_request['requested_scope'].value
                if requested_scope_id in user_permissions or
                   requested_scope_id not in ODPScope.__members__.values()
            ],
            authorized_api_uris=consent_request['requested_access_token_audience'].value,
            access_token_data=user_permissions,
            id_token_data=asdict(user_info),
        )
        return redirect(redirect_to)

    except x.ODPIdentityError as e:
        redirect_to = hydra_admin_api.reject_consent_request(challenge, e.error_code, e.error_description)
        return redirect(redirect_to)


@bp.route('/logout')
def logout():
    """
    Implements the logout provider component of the Hydra logout workflow.
    Hydra redirects to this endpoint based on the ``URLS_LOGOUT`` environment
    variable configured on the Hydra server.
    """
    challenge = request.args.get('logout_challenge')
    logout_request = hydra_admin_api.get_logout_request(challenge)
    redirect_to = hydra_admin_api.accept_logout_request(challenge)
    return redirect(redirect_to)
