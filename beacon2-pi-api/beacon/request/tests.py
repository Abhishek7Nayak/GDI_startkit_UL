from aiohttp.test_utils import TestClient, TestServer, loop_context
from aiohttp import web
import json
import unittest

'''
def create_app():
    app = web.Application()
    #app.on_startup.append(initialize)
    app.add_routes([web.get('/control', ControlView)])
    app.add_routes([web.get('/info', InfoView)])
    return app

class TestRequest(unittest.TestCase):
    def test_request_parameters(self):
        with loop_context() as loop:
            app = create_app()
            client = TestClient(TestServer(app), loop=loop)
            loop.run_until_complete(client.start_server())
            async def test_parameters():
                resp = await client.get("/control?start=1")
                assert resp.status == 200
                text = await resp.text()
                assert json.dumps({'resp': 'hello world'}) == text
            loop.run_until_complete(test_parameters())
            loop.run_until_complete(client.close())

if __name__ == '__main__':
    unittest.main()
'''