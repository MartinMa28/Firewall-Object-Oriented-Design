import unittest
from IPAddressRange import IPAddressRange

class TestIPAddressRange(unittest.TestCase):

    def test_within_range(self):
        test_range = IPAddressRange('192.168.1.1', '192.168.2.5')

        self.assertEqual(True, test_range.within_range('192.168.1.255'))
        self.assertEqual(True, test_range.within_range('192.168.2.4'))
        self.assertEqual(False, test_range.within_range('192.168.1.0'))
        self.assertEqual(False, test_range.within_range('0.0.0.0'))
        self.assertEqual(False, test_range.within_range('255.255.255.255'))