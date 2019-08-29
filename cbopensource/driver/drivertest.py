import unittest
import traceback 
import threatconnect

class TestTcConfig(unittest.TestCase):
    def test_tc_config(self):
        kwargs = { "sources":"Carbon Black",
         "url":"https://api.sandbox.threatconnect.com/api",
          "web_url":"https://api.sandbox.threatconnect.com/auth",
          "api_key":"adfasfdsa",
          "secret_key":"asfdsafdsa",
          "default_org":"Carbon Black",
          "ioc_types":"file"}
        try:
            tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        except Exception as e:
            self.fail("Unexpected config error when construction threat connect config {0}".format(traceback.format_exc()))

    def test_tc_config_all_types_if_none(self):
        kwargs = { "sources":"Carbon Black",
         "url":"https://api.sandbox.threatconnect.com/api",
          "web_url":"https://api.sandbox.threatconnect.com/auth",
          "api_key":"adfasfdsa",
          "secret_key":"asfdsafdsa",
          "default_org":"Carbon Black"}
        try:
            tcconfig = threatconnect.ThreatConnectConfig(**kwargs)
        except Exception as e:
            self.fail("Unexpected config error when construction threat connect config {0}".format(traceback.format_exc()))

    def test_tc_config_bad_ioc_min(self):
        kwargs = { "sources":"Carbon Black",
         "url":"https://api.sandbox.threatconnect.com/api",
          "web_url":"https://api.sandbox.threatconnect.com/auth",
          "api_key":"adfasfdsa",
          "secret_key":"asfdsafdsa",
          "default_org":"Carbon Black",
          "ioc_min_rating": 6}
        with self.assertRaises(ValueError):
            tcconfig = threatconnect.ThreatConnectConfig(**kwargs)

    def test_tc_config_bad_configs(self):
        kwargs = { "sources":"Carbon Black",
         "url":"https://api.sandbox.threatconnect.com/api",
          "web_url":"https://api.sandbox.threatconnect.com/auth",
          "api_key":"adfasfdsa",
          "secret_key":"asfdsafdsa",
          "default_org":"Carbon Black"}
        toremove = ["url","web_url","api_key","secret_key"]
        for remove in toremove:
            with self.assertRaises(ValueError):
                mykwargs = kwargs.copy()
                del mykwargs[remove]
                tcconfig = threatconnect.ThreatConnectConfig(**mykwargs)

if __name__ == "__main__":
    unittest.main()