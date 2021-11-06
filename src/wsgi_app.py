from gevent import monkey

monkey.patch_all()

from app import create_app  # noqa: E402,F401

app = create_app()
