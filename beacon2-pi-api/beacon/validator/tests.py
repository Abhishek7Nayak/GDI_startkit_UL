
from aiohttp.test_utils import TestClient, TestServer, loop_context
from aiohttp import web
import unittest
from beacon.validator.validator import info_check, load_json_from_url


def create_app():
    app = web.Application()
    #app.on_startup.append(initialize)
    return app

class TestValidator(unittest.TestCase):
    def test_validator_catching_errors_load_json_from_url(self):
        with loop_context() as loop:
            app = create_app()
            client = TestClient(TestServer(app), loop=loop)
            loop.run_until_complete(client.start_server())
            async def test_catching_errors_load_json_from_url():
                resp = load_json_from_url('http://localhost:5050/contro')
                assert resp.status == 404
            loop.run_until_complete(test_catching_errors_load_json_from_url())
            loop.run_until_complete(client.close())


if __name__ == '__main__':
    unittest.main()# pragma: no cover

'''    def test_info_validate_info_schema(self):
        with loop_context() as loop:
            app = create_app()
            client = TestClient(TestServer(app), loop=loop)
            loop.run_until_complete(client.start_server())
            async def test_validate_info():
                resp = info_check('http://localhost:5070/info')
                assert []==resp
            loop.run_until_complete(test_validate_info())
            loop.run_until_complete(client.close())'''


