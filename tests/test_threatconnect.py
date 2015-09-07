__author__ = 'jgarman'

import unittest
from cbopensource.connectors.threatconnect.bridge import CarbonBlackThreatConnectBridge, ThreatConnectFeedGenerator
import os


class ThreatConnectTest(unittest.TestCase):
    def setUp(self):
        my_directory = os.path.dirname(os.path.abspath(__file__))
        self.bridge = CarbonBlackThreatConnectBridge("threatconnect", os.path.join(my_directory, "testing.conf"),
                                                     logfile='/tmp/threatconnect.log', pidfile='/tmp/threatconnect.pid',
                                                     debug=True)
        self.bridge.validate_config()

    def testConnection(self):
        auth = self.bridge.bridge_auth
        tc = ThreatConnectFeedGenerator(auth["api_key"], auth['api_secret_key'],
                                        auth["url"], self.bridge.api_urns.items())

        new_iocs = tc.get_threatconnect_iocs()
        print len(new_iocs)
