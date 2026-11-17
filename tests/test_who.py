import ast
import asyncio
import copy
import datetime
import logging
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, Mock, patch

from lib import dxtelnet


def response(name):
    fields = dxtelnet.struct.Struct('10s 8s 18s 11s 2x 5s').pack(
        b'USER'.ljust(10), b'Connect'.ljust(8), b'18-Nov-2026 0000Z'.ljust(18), name.ljust(11), b'0.1'.ljust(5))
    return b'Callsign Type State Started Name RTT\r\nPA1ABC ' + fields + b'\r\ndxspider >'


class WhoTests(unittest.TestCase):
    def test_legacy_and_utf8_names_preserve_columns(self):
        for name in (b'Andr\xe9', 'André'.encode()):
            row = dxtelnet.parse_who(response(name))[0]
            self.assertEqual(row['name'], 'André')
            self.assertEqual(row['average_rtt'], '0.1')
            self.assertEqual(row['callsign'], 'PA1ABC')

    def test_fetch_legacy_name(self):
        reader = Mock()
        reader.readuntil = AsyncMock(side_effect=[response(b'Andr\xe9'),
            b'DXSpider v1.57 (build 687 git: mojo/test)\r\ndxspider >'])
        writer = Mock()
        with patch.object(dxtelnet, '_telnet_login', AsyncMock(return_value=(reader, writer))):
            rows, version = asyncio.run(dxtelnet.fetch_who_and_version('test', 7300, 'test'))
        self.assertEqual(rows[0]['name'], 'André')
        self.assertEqual(version, 'DXSpider v1.57 build 687')
        writer.close.assert_called_once()

    def test_fetch_errors_propagate_and_close_connection(self):
        for error in (asyncio.TimeoutError(), EOFError(), OSError('connection lost')):
            reader = Mock()
            reader.readuntil = AsyncMock(side_effect=error)
            writer = Mock()
            with patch.object(dxtelnet, '_telnet_login', AsyncMock(return_value=(reader, writer))):
                with self.assertRaises(type(error)):
                    asyncio.run(dxtelnet.fetch_who_and_version('test', 7300, 'test'))
            writer.close.assert_called_once()

    def test_failed_refresh_preserves_cache(self):
        # Load just the refresh function, avoiding production startup and timers.
        tree = ast.parse(Path('webapp.py').read_text())
        func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'who_is_connected')
        initial = {'data': [{'callsign': 'PA1ABC'}], 'version': '687',
                   'last_updated': 'previous', 'last_success': 'previous'}
        for result in (None, ([], 'Unknown')):
            state = copy.deepcopy(initial)
            ns = dict(whoj=state, cfg={'telnet': dict(telnet_host='test', telnet_port=7300,
                      telnet_user='test', telnet_password='')}, logger=Mock(), asyncio=asyncio,
                      fetch_who_and_version=AsyncMock(return_value=result), threading=Mock(), TIMER_WHO=420)
            exec(compile(ast.Module(body=[func], type_ignores=[]), 'webapp.py', 'exec'), ns)
            ns['who_is_connected']()
            for key, value in initial.items():
                self.assertEqual(state[key], value)
            self.assertEqual(state['status'], 'error')
            ns['threading'].Timer.assert_called_once()


if __name__ == '__main__':
    unittest.main()
