import traceback
import logging
import time
import threading
import argparse
import configparser
from datetime import (datetime,timedelta)
from threading import Event
from feed import CbFeed, CbFeedInfo, CbReport
from threatconnect import ThreatConnect
from threatconnect.Config.FilterOperator import FilterOperator
import json
import os
import sys


logging_format = '%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s'
logging.basicConfig(format=logging_format)

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class ThreatConnectConfigurationError(Exception):
    def __init__(self, message):
        self.message = message

class CbThreatConnectConnector(object):

    def __init__(self,access_id,secret_key,default_org,base_url,polling_interval,outfile,sources,ioc_types,ioc_min=None,niceness=None,debug=False,logfile=None):
        logger.info("base url = {0}".format(base_url))

        self.tcapi = ThreatConnect(api_aid=access_id,api_sec=secret_key,api_url=base_url,api_org=default_org)

        self.sources = sources

        self.ioc_min = ioc_min

        self.ioc_types = ioc_types

        if self.sources[0] == "*":
            owners = self.tcapi.owners()
            try:
                # retrieve the Owners
                owners.retrieve()
            except RuntimeError as e:
                print('Error: {0}'.format(e))
                sys.exit(1)
            # iterate through the Owners
            self.sources = [owner.name for owner in owners]

        self.niceness = niceness
        if self.niceness is not None:
            os.nice(self.niceness)

        self.debug = debug

        self.logfile = logfile

        self.outfile = outfile

        specs = {"M": "minutes", "W": "weeks", "D": "days", "S": "seconds", "H": "hours"}
        spec = specs[polling_interval[-1].upper()]
        val = int(polling_interval[:-1])
        self.interval = timedelta(**{spec: val})

        self.stopEvent = Event()

    def stop(self):
        self.stopEvent.set()

    @debug.getter
    def debug(self):
        return self._debug

    @debug.setter
    def setDebugMode(self,debugOn):
        self._debug = debugOn
        if self._debug == True:
            logger.setLevel(logging.DEBUG)

    def _PollThreatConnect(self):
        last = None
        while(True):
            if self.stopEvent.isSet():
                logger.info("Threatconnect Connector was signalled to stop...stopping")
                break
            else:
                #poll threat connect if the time delta has passed since the last time we did
                now = datetime.now()
                delta = now - last if last is not None else self.interval
                last = now
                if delta >= self.interval:
                    self.generate_feed_from_threatconnect()
                else:
                    time.sleep(delta.seconds)

    def RunForever(self):
        threading.Thread(target=self._PollThreatConnect).start()

    def generate_feed_from_threatconnect(self):
        #print ("BEGIN FEED GEN")
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
        feed = CbFeed(feedinfo, reports)
        logger.debug("dumping feed...")
        created_feed = feed.dump(validate=False,indent=0)
        logger.debug("Writing out feed to disk")
        with open(self.outfile, 'w') as fp:
            fp.write(created_feed)
            offset = len(created_feed)-1
            #print ("DONE FEED INIT")
            # create an Indicators object
            for source in self.sources:
                for type in self.ioc_types:
                    indicators = self.tcapi.indicators()
                    filter1 = indicators.add_filter()
                    filter1.add_owner(source)
                    filter1.add_pf_type(type,FilterOperator.EQ)
                    if self.ioc_min is not None:
                        filter1.add_pf_rating(self.ioc_min,FilterOperator.GE)
                    try:
                        # retrieve Indicators
                        indicators.retrieve()
                    except RuntimeError as e:
                        print('Error: {0}'.format(e))

                    for indicator in indicators:
                        #print (indicator.type)
                        score = indicator.rating * 20 if indicator.rating is not None else 0
                        #int(row.get('rating', 0)) * 20
                        # Many entries are missing a description so I placed this here to default them
                        # to the IOC value in the absence of a description.
                        title = indicator.description if indicator.description is not None else "{0}-{1}".format(source,indicator.id)# row.get('description', None)
                        #if not title:
                        #    title = row.get('summary')
                        fields = {'iocs': {},
                                  'id': str(indicator.id),
                                  'link': indicator.weblink,
                                  'title': title,
                                  'score': int(score),
                                  'timestamp': int(datetime.strptime(indicator.date_added,"%Y-%m-%dT%H:%M:%SZ").timestamp()),
                                  }
                        # The next few lines are designed to insert the Cb supported IOCs into the record.
                        if indicator.type == "File":
                            fields['iocs'] = {k : [indicator.indicator[k]] for k in indicator.indicator if indicator.indicator[k] is not None}
                        elif indicator.type == "Address":
                            fields['iocs']['ipv4'] = [indicator.indicator]
                        elif indicator.type == "Host":
                            fields['iocs']['dns'] = [indicator.indicator]
                        report = CbReport(**fields)
                        fp.seek(offset-2)
                        fp.write(("," if not first else "")+str(report.dump(validate=False))+"]}")
                        offset = fp.tell()

def main(configfile):
    cfg = verify_config(configfile)
    threatconnectconnector = CbThreatConnectConnector(**cfg)
    threatconnectconnector.RunForever()
    #threatconnectconnector.generate_feed_from_threatconnect()

def verify_config(config_file):

    cfg = {}

    config = configparser.ConfigParser()
    config.read(config_file)

    if not config.has_section('general'):
        raise ThreatConnectConfigurationError('Config does not have a \'general\' section.')

    if not 'polling_interval' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'polling_interval\' key-value pair.")
    else:
        cfg['polling_interval'] = config['general']['polling_interval']

    if 'niceness' in config['general']:
        #os.nice(int(config['general']['niceness']))
        cfg['niceness'] = int(config['general']['niceness'])

    if 'debug' in config['general']:
        # os.nice(int(config['general']['niceness']))
        cfg['debug'] = bool(config['general']['debug'])

    if not 'logfile' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'logfile\' key-value pair.")
    else:
        cfg['logfile'] = config['general']['logfile']

    if not 'outfile' in config['general']:
        raise ThreatConnectConfigurationError("Config does not have an \'outfile\' key-value pair.")
    else:
        cfg['outfile'] = config['general']['outfile']

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
        cfg['ioc_types'] = ['File','Address','Host']

    return cfg

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Agent for ThreatConnect Connector')
    parser.add_argument('--config-file',
                        required=True,
                        default='threatconnect.conf',
                        help='Location of the config file')

    args = parser.parse_args()
    try:
        main(args.config_file)
    except:
        logger.error(traceback.format_exc())