#!/usr/bin/env python3

import time
from icq_client import ICQClient, S_ONLINE, XSTATUS_MOBILE


SERVER = "kicq.ru"
PORT = "5190"
UIN  = 0
PASSWORD = "password"

c = ICQClient()
c.icq_server = SERVER
c.icq_port = PORT
c.uin, c.password = UIN, PASSWORD
c.on_login = lambda cl: (cl.set_xstatus(XSTATUS_MOBILE, "Test!!!", "Testing XStatus!"), print("Login successful with UIN:", UIN))
c.on_message_recv = lambda cl, msg, uin: cl.send_message(uin, msg)
c.on_auth_request = lambda cl, uin, _: cl.send_auth_response(uin, True)

c.login(S_ONLINE)


if not c.wait_login(90):
    raise SystemExit("Login failed!")

try:
    while c.logged_in:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    c.logoff()
