
import unittest
import json
from hyp3rarmor.common.token import *
from hyp3rarmor.common.constants import MAX_PORT_NUMBER

class TestToken(unittest.TestCase):

    def setUp(self):
        self.dports = [1,2,3]
        self.token = Token(60, dports=self.dports )

    def tearDown(self):
        self.token = None

    def test_to_json(self):
        json_string = self.token.to_json()
        obj = json.loads(json_string)
        self.assertEqual(self.dports, obj["dports"])
        self.assertIsInstance(obj["expire"], float)
        self.assertGreater(obj["expire"], 0)

        self.assertIsInstance(obj["ttl"], int)
        self.assertGreater(obj["ttl"], 0)


class TestGenerateUniversalToken(unittest.TestCase):
    def setUp(self):
        ttl = 60
        self.length = 1
        self.token = UniversalToken(60, self.length)

    def test_generate(self):
        self.assertIsInstance(self.token.expire, float)
        self.assertGreater(self.token.expire, 0)
        self.assertIsInstance(self.token.ttl, int)
        self.assertGreater(self.token.ttl, 0)

        self.assertIsInstance(self.token.dports, list)
        self.assertEqual(self.length, len(self.token.dports))

        for dport in self.token.dports:
            self.assertIsInstance(dport, int)
            self.assertGreater(dport, 0)
            self.assertLessEqual(dport, MAX_PORT_NUMBER)


if __name__ == '__main__':
    unittest.main()
