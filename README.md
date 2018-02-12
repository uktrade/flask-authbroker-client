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

