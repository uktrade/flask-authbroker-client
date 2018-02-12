import logging
from functools import wraps
from urllib.parse import urljoin

from werkzeug import security
from flask import Blueprint, redirect, url_for, session, request, current_app
from flask_oauthlib.client import OAuth


__all__ = ('authbroker_blueprint', 'NotAuthenticatedError', 'login_required',
           'protect_all_views', 'get_profile', 'is_authenticated')


authbroker_blueprint = Blueprint('auth', __name__)

logger = logging.getLogger(__name__)
oauth = OAuth(current_app)
authbroker_client = None

TOKEN_SESSION_KEY = '_authbroker_token'
PROFILE_PATH = '/api/v1/user/me/'


class NotAuthenticatedError(Exception):
    pass


def _get_client():
    global authbroker_client, get_token

    if not authbroker_client:
        base_url = current_app.config['ABC_BASE_URL']

        authbroker_client = oauth.remote_app(
            'authbroker',
            base_url=base_url,
            request_token_url=None,
            access_token_url=urljoin(base_url, '/o/token/'),
            authorize_url=urljoin(base_url, '/o/authorize/'),
            consumer_key=current_app.config['ABC_CLIENT_ID'],
            consumer_secret=current_app.config['ABC_CLIENT_SECRET'],
            access_token_method='POST',
            request_token_params={
                'state': lambda: security.gen_salt(10)
            }
        )

        get_token = authbroker_client.tokengetter(get_token)

    return authbroker_client


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for('auth.login', next=request.url))

        return f(*args, **kwargs)

    return decorated_function


def protect_all_views(exclude=None):
    exclude = exclude or []

    def _protect_all_views():
        if request.endpoint not in exclude:
            if not is_authenticated():
                return redirect(url_for('login'))

    _protect_all_views = current_app.before_request(_protect_all_views)


def get_profile():
    """Get the user's profile"""
    response = _get_client().get(PROFILE_PATH)

    if response.status != 200:
        raise NotAuthenticatedError

    return response.json()


def logout_user():
    """Kill the session"""
    session.pop(TOKEN_SESSION_KEY, None)


def is_authenticated():
    """Is the current user authenticated with the auth broker?

    TODO: add configurable grace period to avoid verifying on every request"""
    if TOKEN_SESSION_KEY in session:
        me = _get_client().get(PROFILE_PATH)
        if me.status == 200:
            return True

    return False


@authbroker_blueprint.route('/login')
def login():
    """The login view"""
    return _get_client().authorize(callback=url_for('auth.authorised', _external=True))


@authbroker_blueprint.route('/logout')
def logout():
    """The logout view"""
    logout_user()

    return redirect('/')


@authbroker_blueprint.route('/login/authorised')
def authorised():
    """The authorise view"""

    resp = _get_client().authorized_response()

    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp)
    else:
        session[TOKEN_SESSION_KEY] = (resp['access_token'], '')
        return redirect('/')


def get_token():
    """Required by OAuth client - this is wired up in `_get_client()`"""
    return session.get(TOKEN_SESSION_KEY)
