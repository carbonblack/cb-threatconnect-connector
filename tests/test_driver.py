import threading
import unittest

from cbopensource.driver import threatconnect
from tests.utils.threatconnect_mock_server import get_mocked_server


class TestTcDriverMockedServer(unittest.TestCase):

    def setUp(self):
        self.mock_tc_server = get_mocked_server("tests/data")
        kwargs = {"sources": "*",
                  "url": "http://localhost:7982/api",
                  "web_url": "http://localhost:7982/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "ioc_types": "File,Address,Host"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        threatconnect.ThreatConnectDriver.initialize(tcconfig)
        self.driver = threatconnect.ThreatConnectDriver(tcconfig)
        t = threading.Thread(target=self.mock_tc_server.run, args=('127.0.0.1', 7982), kwargs={"debug": False})
        t.daemon = True
        t.start()

    def test_driver_against_mock(self):
        reports = threatconnect.ThreatConnectDriver.generate_reports(self.driver)
        self.assertTrue(reports, "Didn't get any reports!")


class TestTcConfig(unittest.TestCase):
    def test_01_tc_config(self):
        """
        Ensure proper config setting.
        """
        kwargs = {"api_key": "adfasfdsa",
                  "default_org": "Carbon Black",
                  "ioc_types": "file",
                  "secret_key": "asfdsafdsa",
                  "sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  }
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual(kwargs["api_key"], tcconfig.api_key)
        self.assertEqual(kwargs["default_org"], tcconfig.default_org)
        self.assertEqual(0, len(tcconfig.filtered_hashes))
        self.assertIsNone(tcconfig.filtered_hashes_file)
        self.assertEqual(0, len(tcconfig.filtered_hosts))
        self.assertIsNone(tcconfig.filtered_hosts_file)
        self.assertEqual(0, len(tcconfig.filtered_ips))
        self.assertIsNone(tcconfig.filtered_ips_file)
        self.assertEqual(threatconnect.IocGrouping.Expanded, tcconfig.ioc_grouping)
        self.assertEqual(1, tcconfig.ioc_min_rating)
        self.assertEqual(1, len(tcconfig.ioc_types))
        self.assertEqual(threatconnect.FileIoc, type(tcconfig.ioc_types[0]))
        self.assertEqual(0, tcconfig.max_reports)
        self.assertEqual(kwargs["secret_key"], tcconfig.secret_key)
        self.assertListEqual([kwargs["sources"]], tcconfig.sources.values)
        self.assertEqual(kwargs["url"], tcconfig.url)
        self.assertEqual(kwargs["web_url"], tcconfig.web_url)

    def test_02a_tc_config_ioc_types_missing(self):
        """
        Ensure that all IOC types are used if not specified.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual(3, len(tcconfig.ioc_types))  # should be Host, File, Address

    def test_02b_tc_config_ioc_types_multiple(self):
        """
        Ensure that multiple IOC types can be specified if comma-separated.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "ioc_types": "file,    host",  # extra spaces should be trimmed
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual(2, len(tcconfig.ioc_types))  # should be Host, File
        for item in tcconfig.ioc_types:
            assert type(item) in [threatconnect.FileIoc, threatconnect.HostIoc]

    def test_02c_tc_config_ioc_types_duplicate(self):
        """
        Ensure that multiple IOC types can be specified if comma-separated.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "ioc_types": "file,    file",  # extra spaces should be trimmed
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual(1, len(tcconfig.ioc_types))  # should be File
        assert type(tcconfig.ioc_types[0]) == threatconnect.FileIoc

    def test_02d_tc_config_ioc_types_bogus(self):
        """
        Ensure that invalid IOC types are caught.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "ioc_types": "BOGUS",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black"}
        with self.assertRaises(ValueError) as err:
            threatconnect.ThreatConnectConfig(**kwargs)
        assert "BOGUS is not a valid IocType" in err.exception.args[0]

    def test_03a_tc_config_ioc_min_invalid(self):
        """
        Ensure an invalid IOC min rating (greater than 5) is caught.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "ioc_min_rating": 6}
        with self.assertRaises(ValueError) as err:
            threatconnect.ThreatConnectConfig(**kwargs)
        assert "value must be a number between 0 and 5." in err.exception.args[0]

    def test_03b_tc_config_ioc_min_invalid_negative(self):
        """
        Ensure an invalid IOC min rating (less than 0) is caught.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "ioc_min_rating": -1}
        with self.assertRaises(ValueError) as err:
            threatconnect.ThreatConnectConfig(**kwargs)
        assert "value must be a number between 0 and 5." in err.exception.args[0]

    def test_03c_tc_config_ioc_min_bogus(self):
        """
        Ensure an bogus IOC min rating (not an int) is caught.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "ioc_min_rating": "text"}
        with self.assertRaises(ValueError) as err:
            threatconnect.ThreatConnectConfig(**kwargs)
        assert "value must be a number between 0 and 5." in err.exception.args[0]

    def test_04a_tc_config_ioc_grouping_allowed(self):
        """
        Ensure that all IOC groupings can be specified.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black"}
        groupings = [("expanded", threatconnect.IocGrouping.Expanded),
                     ("condensed", threatconnect.IocGrouping.Condensed),
                     ("maxcondensed", threatconnect.IocGrouping.MaxCondensed)]
        for group in groupings:
            mykwargs = kwargs.copy()
            mykwargs["ioc_grouping"] = group[0]
            tconfig = threatconnect.ThreatConnectConfig(**mykwargs)
            assert tconfig.ioc_grouping == group[1]

    def test_04b_tc_config_ioc_grouping_bogus(self):
        """
        Ensure that bogus IOC grouping is detected.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "ioc_grouping": "BOGUS",
                  "default_org": "Carbon Black"}
        with self.assertRaises(ValueError) as err:
            threatconnect.ThreatConnectConfig(**kwargs)
        assert "BOGUS is not a valid IocGrouping" in err.exception.args[0]

    def test_05_tc_config_missing_requireds(self):
        """
        Ensure that missing required fields is caught.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black"}
        toremove = ["url", "web_url", "api_key", "secret_key"]
        for remove in toremove:
            mykwargs = kwargs.copy()
            del mykwargs[remove]
            with self.assertRaises(ValueError) as err:
                threatconnect.ThreatConnectConfig(**mykwargs)
            assert "option missing" in err.exception.args[0]

    def test_06_tc_config_max_reports_bogus(self):
        """
        Ensure that bogus (non-int) max reports is caught
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "max_reports": "BOGUS"}
        with self.assertRaises(ValueError) as err:
            threatconnect.ThreatConnectConfig(**kwargs)
        assert "invalid literal for int()" in err.exception.args[0]

    def test_07a_tc_config_filter_files(self):
        """
        Ensure that filter files can be processed properly.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "filtered_ips": "./data/filter_set.txt"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual("./data/filter_set.txt", tcconfig.filtered_ips_file)
        self.assertEqual(3, len(tcconfig.filtered_ips))

        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "filtered_hashes": "./data/filter_set.txt"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual("./data/filter_set.txt", tcconfig.filtered_hashes_file)
        self.assertEqual(3, len(tcconfig.filtered_hashes))

        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "filtered_hosts": "./data/filter_set.txt"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual("./data/filter_set.txt", tcconfig.filtered_hosts_file)
        self.assertEqual(3, len(tcconfig.filtered_hosts))

    def test_07b_tc_config_tc_config_filter_files_missing(self):
        """
        Ensure that missing filter file is caught.
        """
        kwargs = {"sources": "Carbon Black",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "filtered_hosts": "./no-such-filter-file"}
        with self.assertRaises(ValueError) as err:
            threatconnect.ThreatConnectConfig(**kwargs)
        assert "No such file or directory" in err.exception.args[0]

    def test_08a_tc_config_sources_multiple(self):
        """
        Ensure that comma-separated sources are handled correctly.
        """
        kwargs = {"sources": "Carbon Black,     Bit-9  , VMWare",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "filtered_ips": "./data/filter_set.txt"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual(3, len(tcconfig.sources.values))
        self.assertFalse(tcconfig.sources.all)
        for item in tcconfig.sources.values:
            self.assertTrue(item in ["Carbon Black", "Bit-9", "VMWare"])

    def test_08b_tc_config_sources_all(self):
        """
        Ensure that * source is handled correctly..
        """
        kwargs = {"sources": "  *  ",
                  "url": "https://api.sandbox.threatconnect.com/api",
                  "web_url": "https://api.sandbox.threatconnect.com/auth",
                  "api_key": "adfasfdsa",
                  "secret_key": "asfdsafdsa",
                  "default_org": "Carbon Black",
                  "filtered_ips": "./data/filter_set.txt"}
        tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        self.assertEqual(0, len(tcconfig.sources.values))
        self.assertTrue(tcconfig.sources.all)


if __name__ == "__main__":
    unittest.main()
