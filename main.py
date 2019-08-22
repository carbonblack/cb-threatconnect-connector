from cbopensource.connectors.threatconnect import bridge

if __name__ == "__main__":
    name = "cb-threatconnect-connector"
    daemon = bridge.CarbonBlackThreatConnectBridge(name, configfile="run/connector_test.conf", logfile="run/debug.log",
                                                   debug=True)
    daemon.start()
