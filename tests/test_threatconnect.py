__author__ = 'jgarman'

import unittest
from cbopensource.connectors.threatconnect.bridge import CarbonBlackThreatConnectBridge, ThreatConnectFeedGenerator
import os
from utils import threatconnect_mock_server
import threading


class ThreatConnectTest(unittest.TestCase):
    def setUp(self):
        my_directory = os.path.dirname(os.path.abspath(__file__))
        self.bridge = CarbonBlackThreatConnectBridge("threatconnect",
                                                     os.path.join(my_directory, "mock_threatconnect.conf"),
                                                     logfile='/tmp/threatconnect.log', pidfile='/tmp/threatconnect.pid',
                                                     debug=True)
        self.bridge.validate_config()

        data_dir = os.path.abspath(os.path.join(my_directory, 'data'))
        self.mock_server = threatconnect_mock_server.get_mocked_server(data_dir)
        tc_thread = threading.Thread(target=self.mock_server.run, args=('127.0.0.1', 7982))
        tc_thread.daemon = True
        tc_thread.start()

    def testConnection(self):
        auth = self.bridge.bridge_auth
        tc = ThreatConnectFeedGenerator(auth["api_key"], auth['api_secret_key'],
                                        auth["url"], self.bridge.api_urns.items())

        new_iocs = tc.get_threatconnect_iocs()
        print len(new_iocs)
