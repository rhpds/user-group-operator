#!/usr/bin/env python3

import unittest
import sys
sys.path.append('../operator')

from simplejinja import jinja2process

class TestJsonPatch(unittest.TestCase):
    def test_00(self):
        template = {}
        template_vars = {}
        self.assertEqual(
            jinja2process("no-vars"),
            "no-vars"
        )

    def test_01(self):
        template = {}
        template_vars = {
            "b64str": "SGVsbG8sIFdvcmxkCg",
        }
        self.assertEqual(
            jinja2process("{{ b64str | b64decode }}", variables=template_vars),
            "Hello, World\n"
        )

    def test_02(self):
        template = {}
        template_vars = {
            "data": {
                "foo": "bar",
            },
        }
        self.assertEqual(
            jinja2process("{{ data | json_query('foo') }}", variables=template_vars),
            "bar"
        )

if __name__ == '__main__':
    unittest.main()
