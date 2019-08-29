import unittest
import traceback 
import theatconnect

class TestTcConfig(unittest.TestCase):
    def test_tc_config(self):
        kwargs = { "sources":"Carbon Black",
         "url":"https://api.sandbox.threatconnect.com/api",
          "web_url":"https://api.sandbox.threatconnect.com/auth",
          "api_key":"adfasfdsa",
          "secret_key":"asfdsafdsa",
          "default_org":"Carbon Black"}
        try:
            tcconfig = theatconnect.ThreatConnectConfig(**kwargs)
        except Exception as e:
            self.fail("Unexpected config error when construction threat connect config {0}".format(traceback.format_exc()))

if __name__ == "__main__":
    unittest.main()