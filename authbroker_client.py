import logging
import warnings
from functools import wraps
from urllib.parse import urljoin, urlparse

from werkzeug import security
from flask import Blueprint, redirect, url_for, session, request, current_app

# ATTENTION: Flask-OAuthLib is deprecated
# Authlib (https://github.com/lepture/authlib) should be used instead
try:
    # newer projects
    from authlib.integrations.flask_client import OAuth
except ImportError:
    # this is a fallback import to allow existing projects time to update Flask/Werkzeug
    warnings.warn("deprecated", DeprecationWarning)
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
        conf = current_app.config

        base_url = conf['ABC_BASE_URL']

        request_token_params = {
            'state': lambda: security.gen_salt(10)
        }
        test_sso_return_token = conf.get('ABC_TEST_SSO_RETURN_ACCESS_TOKEN')
        if test_sso_return_token:
            request_token_params['code'] = test_sso_return_token

        authbroker_client = oauth.remote_app(
            'authbroker',
            base_url=base_url,
            request_token_url=None,
            access_token_url=urljoin(base_url, '/o/token/'),
            authorize_url=urljoin(base_url, '/o/authorize/'),
            consumer_key=conf['ABC_CLIENT_ID'],
            consumer_secret=conf['ABC_CLIENT_SECRET'],
            access_token_method='POST',
            request_token_params=request_token_params,
        )

        get_token = authbroker_client.tokengetter(get_token)

    return authbroker_client


def _is_safe_url(target_url):
    """
    Checks if the URL is for our host name.

    Used to protect against redirects to other, potentially malicious, websites.

    Based on http://flask.pocoo.org/snippets/62/
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target_url))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def _get_next_url():
    if 'next' in request.args:
        next_url = request.args['next']
    elif 'next' in session:
        next_url = session.pop('next', None)
    else:
        next_url = '/'

    return next_url


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
    # `next` is added to the query string by @login_required (from above)
    next_url = request.args.get('next')

    if next_url and _is_safe_url(next_url):
        # Store the originally-requested URL in the session so that it is picked up
        # by _get_next_url() when the user returns from ABC
        session['next'] = next_url

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
        return redirect(_get_next_url())


def get_token():
    """Required by OAuth client - this is wired up in `_get_client()`"""
    return session.get(TOKEN_SESSION_KEY)
