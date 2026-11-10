import datetime
import logging

from flask import Flask

from . import db as dbm
from .config import from_env
from .dnsops import Dns


def create_app(cfg=None, dns=None):
    cfg = cfg or from_env()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=cfg.secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cfg.cookie_secure,
        PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=12),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    app.extensions["cfg"] = cfg
    app.extensions["dns"] = dns or Dns(cfg)
    dbm.init_db(cfg.db_path)

    from . import web
    web.register(app)
    return app
