import urllib.request
from rjscan.callback import CallbackServer


def test_callback_flow():
    server = CallbackServer("127.0.0.1", 0)
    server.start()
    try:
        base = server.address
        token = "abc123"
        url = f"{base}/?token={token}"
        urllib.request.urlopen(url).read()
        event = server.registry.get(token)
        assert event is not None
        assert token == event.token
    finally:
        server.stop()
