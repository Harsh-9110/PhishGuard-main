"""Flask production adapter; the same WSGI core also runs without dependencies."""
from service import Application

core = Application()
try:
    from flask import Flask
except ModuleNotFoundError as exc:
    if exc.name != 'flask':
        raise
    app = core
    RUNTIME_ADAPTER = 'stdlib-wsgi'
else:
    app = Flask(__name__)
    app.wsgi_app = core
    RUNTIME_ADAPTER = 'flask'
