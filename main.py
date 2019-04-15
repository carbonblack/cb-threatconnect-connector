import traceback
import logging
from logging import handlers
import time
import argparse
import configparser
from datetime import datetime
from feed import CbFeed, CbFeedInfo, CbReport
from cbapi.response import CbResponseAPI
from threatconnect import ThreatConnect
from threatconnect.Config.FilterOperator import FilterOperator
import os
import sys

logging_format = '%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s'
logging.basicConfig(format=logging_format)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ThreatConnectConfigurationError(Exception):
    def __init__(self, message):
        self.message = message


class CbThreatConnectConnector(object):

    def __init__(self,
                 access_id="",
                 secret_key="",
                 default_org="",
                 base_url="",
                 out_file="tc.json",
                 sources="",
                 ioc_types="",
                 custom_ioc_key="",
                 feed_url="",
                 cb_server_token="",
                 cb_server_url="https://127.0.0.1",
                 cb_server_ssl_verify=False,
                 ioc_min=None,
                 niceness=None,
                 debug=False,
                 log_file=None,
                 max_iocs=5000):
        logger.info("ThreatConnect Base URL: {0}".format(base_url))

        self.tcapi = ThreatConnect(api_aid=access_id, api_sec=secret_key, api_url=base_url, api_org=default_org)

        self.sources = sources

        self.ioc_min = ioc_min

        self.ioc_types = ioc_types

        logger.info("Configured IOC Types are : {0}".format(self.ioc_types))
        logger.info("Configured IOC Min is  : {0}".format(self.ioc_min))

        self.custom_ioc_key = custom_ioc_key

        self.max_iocs = max_iocs

        if self.sources[0] == "*":
            owners = self.tcapi.owners()
            try:
                # retrieve the Owners
                owners.retrieve()
            except RuntimeError as e:
                logger.error(traceback.format_exc())
                sys.exit(1)
            # iterate through the Owners
            self.sources = [owner.name for owner in owners]

        logger.info("Sources = {0}".format(self.sources))

        self.niceness = niceness
        if self.niceness is not None:
            os.nice(self.niceness)

        self.debug = debug
        if self.debug:
            logger.setLevel(logging.DEBUG)

        self.log_file = log_file

        self.out_file = out_file

        self.feed = None

        self.cb = CbResponseAPI(url=cb_server_url, token=cb_server_token, ssl_verify=cb_server_ssl_verify)

        self.feed_url = feed_url

    def stop(self):
        self.stopEvent.set()

    def getDebugMode(self):
        return self._debug

    def setDebugMode(self,debugOn):
        self._debug = debugOn
        if self._debug == True:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

    debug = property(getDebugMode,setDebugMode)

    def _PollThreatConnect(self):
        self.generate_feed_from_threatconnect()
        self.createFeed()
        last = None
        while(True):
            if self.stopEvent.isSet():
                logger.info("Threatconnect Connector was signalled to stop...stopping")
                return
            else:
                #poll threat connect if the time delta has passed since the last time we did
                now = datetime.now()
                delta = now - last if last is not None else self.interval
                last = now
                if delta >= self.interval:
                    self.generate_feed_from_threatconnect()
                else:
                    time.sleep(self.interval.seconds + 1)
                    logger.debug("Done sleeping...")

    def RunForever(self):
        logger.info("ThreatConnect agent starting...")
        threading.Thread(target=self._PollThreatConnect).start()

    def createFeed(self):
        if self.feed is not None:
            self.feed.upload(self.cb, self.feed_url)

    def generate_feed_from_threatconnect(self):
        first = True
        reports = []
        feedinfo = {'name': 'threatconnect',
                    'display_name': "ThreatConnect",
                    'provider_url': "http://www.threatconnect.com",
                    'summary': "Sends threat intelligence from Threatconnect platform to Carbon Black Response",
                    'tech_data': "There are no requirements to share any data with Carbon Black to use this feed.",
                    'icon': 'threatconnect-logo.png',
                    'category': "Connectors",
                    }

        feedinfo = CbFeedInfo(**feedinfo)
        self.feed = CbFeed(feedinfo, reports)
        created_feed = self.feed.dump(validate=False, indent=0)
        with open(self.out_file, 'w') as fp:
            fp.write(created_feed)

            
            fp.seek(0)
  
            offset = len(created_feed)-1

            # create an Indicators object
            for source in self.sources:
                for t in self.ioc_types:
                    indicators = self.tcapi.indicators()
                    filter1 = indicators.add_filter()
                    # filter1.add_owner(source)
                    filter1.add_pf_type(t, FilterOperator.EQ)
                    if self.ioc_min is not None:
                        filter1.add_pf_rating(self.ioc_min, FilterOperator.GE)
                    try:
                        # retrieve Indicators
                        indicators.retrieve()
                    except RuntimeError as e:
                        print('Error: {0}'.format(e))

                    logger.info("Number of indicators:{0}".format(len(indicators)))

                    for index, indicator in enumerate(indicators):

                        if index > self.max_iocs:
                            logger.info("Max number of IOCs reached")
                            break
                        # print (indicator.type)
                        score = indicator.rating * 20 if indicator.rating is not None else 0
                        # int(row.get('rating', 0)) * 20
                        # Many entries are missing a description so I placed this here to default them
                        # to the IOC value in the absence of a description.
                        title = indicator.description if indicator.description is not None else "{0}-{1}".format(source,
                                                                                                                 indicator.id)  # row.get('description', None)
                        # if not title:
                        #    title = row.get('summary')
                        fields = {'iocs': {},
                                  'id': str(indicator.id),
                                  'link': indicator.weblink,
                                  'title': title,
                                  'score': int(score),
                                  'timestamp': int(
                                      datetime.strptime(indicator.date_added, "%Y-%m-%dT%H:%M:%SZ").timestamp()),
                                  }
                        # The next few lines are designed to insert the Cb supported IOCs into the record.
                        if indicator.type == "File":
                            fields['iocs'] = {k: [indicator.indicator[k]] for k in indicator.indicator if
                                              indicator.indicator[k] is not None}
                        elif indicator.type == "Address":
                            fields['iocs']['ipv4'] = [indicator.indicator]
                        elif indicator.type == "Host":
                            fields['iocs']['dns'] = [indicator.indicator]
                        else:
                            fields['iocs']['query'] = [{'index_type': 'modules',
                                                        'search_query': "cb.urlver=1&q=" + indicator.indicator[self.custom_ioc_key]}]

                        report = CbReport(**fields)
                        try:
                            report.dump(validate=True)
                        except:
                            logger.info("This query is not valid: {0}".format(indicator.indicator[self.custom_ioc_key]))
                            continue
                        # APPEND EACH NEW REPORT ONTO THE LIST IN THE JSON FEED
                        # THIS METHOD IS VERY LONG LIVED
                        # THIS METHOD CALL WILL LAST FOR
                        #  HOURS -> DAYS IN LARGE ORGS
                        reports.append(report)
                        self.feed = CbFeed(feedinfo, reports)
                    fp.write(self.feed.dump(validate=False, indent=0))



def main(config_file, log_file, out_file):
    cfg = verify_config(config_file)
    cfg['out_file'] = out_file
    cfg['log_file'] = log_file

    threatconnectconnector = CbThreatConnectConnector(**cfg)

    threatconnectconnector.generate_feed_from_threatconnect()
    threatconnectconnector.createFeed()


def verify_config(config_file):
    cfg = {}

    config = configparser.ConfigParser()
    config.read(config_file)

    if not config.has_section('general'):
        raise ThreatConnectConfigurationError('Config does not have a \'general\' section.')

    if 'niceness' in config['general']:
        cfg['niceness'] = int(config['general']['niceness'])
        os.nice(cfg['niceness'])

    if 'debug' in config['general']:
        cfg['debug'] = bool(config['general']['debug'])

    if not 'base_url' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'base_url\' key-value pair.")
    else:
        cfg['base_url'] = config['general']['base_url']

    if not 'secret_key' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'secret_key\' key-value pair.")
    else:
        cfg['secret_key'] = config['general']['secret_key']

    if not 'access_id' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'access_id\' key-value pair.")
    else:
        cfg['access_id'] = config['general']['access_id']

    if not 'default_org' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'default_org\' key-value pair.")
    else:
        cfg['default_org'] = config['general']['default_org']

    if not 'sources' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'sources\' key-value pair.")
    else:
        cfg['sources'] = [s.strip() for s in config['general']['sources'].split(",")]

    if 'ioc_min' in config['general']:
        cfg['ioc_min'] = int(config['general']['ioc_min'])

    if 'ioc_types' in config['general']:
        cfg['ioc_types'] = [s.strip() for s in config['general']['ioc_types'].split(",")]
    else:
        cfg['ioc_types'] = ['File', 'Address', 'Host']

    if 'custom_ioc_key' in config['general']:
        cfg['custom_ioc_key'] = config['general']['custom_ioc_key']
    else:
        cfg['custom_ioc_key'] = 'Query'

    if 'cb_server_token' in config['general']:
        cfg['cb_server_token'] = config['general']['cb_server_token']
    else:
        raise ThreatConnectConfigurationError("Config does not have a 'cb_server_token'")

    if 'cb_server_url' in config['general']:
        cfg['cb_server_url'] = config['general']['cb_server_url']
    else:
        raise ThreatConnectConfigurationError("config does not have a 'cb_server_url'")

    if 'cb_server_ssl_verify' in config['general']:
        cfg['cb_server_ssl_verify'] = True if config['general']['cb_server_ssl_verify'] in ['True', 'true', 'T',
                                                                                            't'] else False
    else:
        cfg['cb_server_ssl_verify'] = True

    if 'feed_url' in config['general']:
        cfg['feed_url'] = config['general']['feed_url']
    else:
        cfg['feed_url'] = "file:///" + cfg['out_file']

    if 'max_iocs' in config['general']:
        cfg['max_iocs'] = int(config['general']['max_iocs'])

    return cfg


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Agent for ThreatConnect Connector')
    parser.add_argument('--config-file',
                        required=True,
                        default='threatconnect.conf',
                        help='Location of the config file')

    parser.add_argument('--log-file',
                        required=False,
                        default='tc_agent.log',
                        help='Location to store log files')

    parser.add_argument('--out-file',
                        required=True,
                        default='threatconnect.json',
                        help='Location of JSON feed data')

    args = parser.parse_args()

    if args.log_file:
        formatter = logging.Formatter(logging_format)
        handler = handlers.RotatingFileHandler(args.log_file, maxBytes=10 * 1000000, backupCount=10)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    try:
        main(args.config_file, args.log_file, args.out_file)
    except:
        logger.error(traceback.format_exc())
