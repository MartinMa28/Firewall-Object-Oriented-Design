import unittest
from Firewall import Firewall

class TestFirewall(unittest.TestCase):
    def test_accept_packet(self):
        fw = Firewall('example_rules.csv')

        self.assertEqual(True, fw.accept_packet("inbound","tcp", 80, "192.168.1.2"))
        self.assertEqual(True, fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
        self.assertEqual(True, fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
        self.assertEqual(False, fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
        self.assertEqual(False, fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))

    
    def test_random_rules(self):
        fw = Firewall('random_test.csv')

        self.assertEqual(True, fw.accept_packet('inbound', 'udp', 49426, '109.240.207.207'))
        self.assertEqual(False, fw.accept_packet('inbound', 'udp', 49426, '109.240.207.208'))
        
        self.assertEqual(True, fw.accept_packet('inbound', 'tcp', 52512, '127.100.6.188'))
        self.assertEqual(False, fw.accept_packet('inbound', 'tcp', 52512, '101.148.144.134'))
        
        self.assertEqual(True, fw.accept_packet('outbound', 'udp', 39128, '76.246.1.221'))
        self.assertEqual(False, fw.accept_packet('inbound', 'udp', 39128, '71.246.1.221'))

        self.assertEqual(True, fw.accept_packet('outbound', 'tcp', 33043, '80.201.159.215'))
        self.assertEqual(False, fw.accept_packet('outbound', 'udp', 33043, '80.201.159.215'))
        self.assertEqual(False, fw.accept_packet('outbound', 'tcp', 33043, '148.196.202.208'))
        