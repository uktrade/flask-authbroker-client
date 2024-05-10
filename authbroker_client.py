import logging
from functools import wraps
from urllib.parse import urljoin, urlparse


from flask import Blueprint, redirect, url_for, session, request, current_app
from authlib.integrations.flask_client import OAuth


__all__ = ('authbroker_blueprint', 'NotAuthenticatedError', 'login_required',
           'protect_all_views', 'get_profile', 'is_authenticated')

TOKEN_SESSION_KEY = '_authbroker_token'
PROFILE_PATH = '/api/v1/user/me/'

authbroker_blueprint = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


def get_session_token(_):
    """
        Required by OAuth client
        - fetches the token from session and not from db
        - needs a param
    """
    return session.get(TOKEN_SESSION_KEY)


oauth = OAuth(current_app, fetch_token=get_session_token)


class NotAuthenticatedError(Exception):
    pass


def _get_client():
    try:
        client = oauth.authbroker
        return client
    except AttributeError:
        conf = current_app.config
        base_url = conf['ABC_BASE_URL']
        client_id = conf['ABC_CLIENT_ID']
        client_secret = conf['ABC_CLIENT_SECRET']
        access_token_url = urljoin(base_url, '/o/token/')
        authorize_url = urljoin(base_url, '/o/authorize/')

        oauth.register(
            name='authbroker',
            client_id=client_id,
            client_secret=client_secret,
            access_token_url=access_token_url,
            authorize_url=authorize_url,
            api_base_url=base_url,
            client_kwargs=None,
        )
        return oauth.authbroker


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


def is_authenticated():
    """Is the current user authenticated with the auth broker?

    TODO: add configurable grace period to avoid verifying on every request"""
    if TOKEN_SESSION_KEY in session:
        me = _get_client().get(
            urljoin(current_app.config['ABC_BASE_URL'], PROFILE_PATH)
        )
        if me.ok:
            return True

    return False


def get_profile():
    """Get the user's profile"""
    response = _get_client().get(urljoin(current_app.config['ABC_BASE_URL'], PROFILE_PATH))
    if response.status_code != 200:
        raise NotAuthenticatedError

    return response.json()


def logout_user():
    """Kill the session"""
    session.pop(TOKEN_SESSION_KEY, None)


@authbroker_blueprint.route('/login')
def login():
    """The login view"""
    # `next` is added to the query string by @login_required (from above)
    next_url = request.args.get('next')

    if next_url and _is_safe_url(next_url):
        # Store the originally-requested URL in the session so that it is picked up
        # by _get_next_url() when the user returns from ABC
        session['next'] = next_url

    return _get_client().authorize_redirect(
        url_for('auth.authorised', _external=True)
    )


@authbroker_blueprint.route('/login/authorised')
def authorised():
    """The authorise view"""

    access_token = _get_client().authorize_access_token()

    if access_token is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            access_token)
    else:
        session[TOKEN_SESSION_KEY] = access_token
        return redirect(_get_next_url())


@authbroker_blueprint.route('/logout')
def logout():
    """The logout view"""
    logout_user()

    return redirect('/')



