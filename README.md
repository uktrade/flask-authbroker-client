# flask-authbroker-client

A Flask blueprint for easily integrating with the DIT Authbroker.

# Installation

`pip install -e git://github.com/uktrade/flask-authbroker-client#egg=authbroker_client`
    
# Usage

```
from authbroker_client import authbroker_blueprint, login_required

app = Flask(...)

app.config['ABC_CLIENT_ID'] = 'client-id--speak-to-webops-team'
app.config['ABC_CLIENT_SECRET'] = 'client-secret--speak-to-webops-team'
app.config['ABC_BASE_URL'] = 'https://authbroker-url/'

app.register_blueprint(authbroker_blueprint)

@app.route('/')
@login_required
def index():
  return 'secured-by-authbroker'
```

Done.

# Use with UKTrade mock-sso package

It is possible to configure this package to work with the [mock-sso service](https://github.com/uktrade/mock-sso).

Mock SSO requires that you provide a non-standard parameter in the query string of the initial GET call of the OAuth flow. (See the [mock-sso docs](https://github.com/uktrade/mock-sso/blob/master/README.md) for more detail.)

This parameter is called `code`. Any services which use THIS library (flask-authbroker-client) could need to undertake automated tests of a stack which uses Staff SSO.

For circumstances like these you will need to prime mock-sso with this `code` parameter.

This is achieved by changing the Flask config for the app which is importing THIS library. You'd achieve this by adding
a line like the following to the "app config" code example in the [Usage section](#usage) above.
```
app.config['ABC_TEST_SSO_RETURN_ACCESS_TOKEN'] = 'someCode'
```
where 'someCode' will then be provided as the `code` param when the user agent is redirected to mock-sso, and in turn
the same 'someCode' value will be present as the `access_token` in the redirect back to your app from mock.sso. (Again,
see the [mock-sso docs](https://github.com/uktrade/mock-sso/blob/master/README.md) for more detail.)
