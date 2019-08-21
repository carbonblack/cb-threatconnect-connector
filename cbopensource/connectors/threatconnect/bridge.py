#
# Copyright 2019 CarbonBlack, Inc
#

import os
import sys
import time
from time import gmtime, strftime
import logging
from logging.handlers import RotatingFileHandler
import threading
from . import version

import simplejson as json
import cbint.utils.feed
import cbint.utils.flaskfeed
import cbint.utils.cbserver
import cbint.utils.filesystem
from cbint.utils.daemon import CbIntegrationDaemon
import shutil
from timeit import default_timer as timer

from cbopensource.driver.theatconnect import ThreatConnectConfig, ThreatConnectDriver
import traceback

from cbapi.response import CbResponseAPI, Feed
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.errors import ServerError

logger = logging.getLogger(__name__)


class TimeStamp(object):
    def __init__(self, stamp=False):
        self._value = gmtime() if stamp else None

    def stamp(self):
        """
        Stamps the value of this TimeStamp with the current time.
        """
        self._value = gmtime()

    def clone(self):
        ts = TimeStamp()
        ts._value = self._value
        return ts
    
    def __str__(self):
        if not self._value:
            return "Never"
        return strftime("%a, %d %b %Y %H:%M:%S +0000", self._value)

    def __repr__(self):
        return "TimeStamp({0})".format(self.__str__())


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


class CarbonBlackThreatConnectBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile, logfile=None, pidfile=None, debug=False):

        CbIntegrationDaemon.__init__(self, name, configfile=configfile, logfile=logfile, pidfile=pidfile, debug=debug)
        template_folder = "/usr/share/cb/integrations/cb-threatconnect-connector/content"
        self.flask_feed = cbint.utils.flaskfeed.FlaskFeed(__name__, False, template_folder)
        self.bridge_options = {}
        self.api_urns = {}
        self.validated_config = False
        self.cb = None
        self.sync_needed = False
        self.feed_name = "threatconnectintegration"
        self.display_name = "ThreatConnect"
        self.feed = {}
        self.directory = template_folder
        self.cb_image_path = "/carbonblack.png"
        self.integration_image_path = "/threatconnect.png"
        self.integration_image_small_path = "/threatconnect-small.png"
        self.json_feed_path = "/threatconnect/json"
        self.feed_lock = threading.RLock()
        self.logfile = logfile
        self.debug = debug
        self.pretty_print_json = False

        self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])

        self.initialize_logging()

        logger.debug("generating feed metadata")

        with self.feed_lock:
            self.feed = cbint.utils.feed.generate_feed(
                self.feed_name,
                summary="Threat intelligence data provided by ThreatConnect to the Carbon Black Community",
                tech_data="There are no requirements to share any data to receive this feed.",
                provider_url="http://www.threatconnect.com/",
                icon_path="%s/%s" % (self.directory, self.integration_image_path),
                small_icon_path="%s/%s" % (self.directory, self.integration_image_small_path),
                display_name=self.display_name,
                category="Partner")
            self.last_sync = TimeStamp()
            self.last_successful_sync = TimeStamp()
            self.feed_ready = False
        
    def _read_cached(self):
        with self.feed_lock:
            if self.feed_ready:
                return
        
        folder = self.bridge_options.get("cache_folder", "./")
        cbint.utils.filesystem.ensure_directory_exists(folder)
        try:
            with open(os.path.join(folder, "reports.cache"), "r") as f:
                reports = json.loads(f.read())
            with self.feed_lock:
                if not self.feed_ready:
                    self.feed["reports"] = reports
                self.feed_ready = True
            logger.info("Reports loaded from cache.")
        except IOError as e:
            logger.warning("Cache file missing or invalid: {0}".format(e))
    
    def initialize_logging(self):

        if not self.logfile:
            log_path = "/var/log/cb/integrations/%s/" % self.namoptse
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = "%s%s.log" % (log_path, self.name)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        root_logger.handlers = []

        rlh = RotatingFileHandler(self.logfile, maxBytes=524288, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(module)s: %(levelname)s: %(message)s"))
        root_logger.addHandler(rlh)

        self.logger = root_logger

    @property
    def integration_name(self):
        return 'Cb ThreatConnect Connector {0}'.format(version.__version__)

    def serve(self):
        if "https_proxy" in self.bridge_options:
            os.environ['HTTPS_PROXY'] = self.bridge_options.get("https_proxy", "")
            os.environ['no_proxy'] = '127.0.0.1,localhost'

        address = self.bridge_options.get('listener_address', '127.0.0.1')
        port = self.bridge_options['listener_port']
        logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=self.debug,
                                host=address, use_reloader=False)

    def handle_json_feed_request(self):
        with self.feed_lock:
            json = self.flask_feed.generate_json_feed(self.feed)
        return json

    def handle_html_feed_request(self):
        with self.feed_lock:
            html = self.flask_feed.generate_html_feed(self.feed, self.display_name)
        return html

    def handle_index_request(self):
        with self.feed_lock:
            index = self.flask_feed.generate_html_index(self.feed, self.bridge_options, self.display_name,
                                                        self.cb_image_path, self.integration_image_path,
                                                        self.json_feed_path, str(self.last_sync))
        return index

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self.directory, self.cb_image_path))

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" %
                                                                  (self.directory, self.integration_image_path))

    def on_starting(self):
        self._read_cached()
        ThreatConnectDriver.initialize(self.tc_config)

    def run(self):
        logger.info("starting Carbon Black <-> ThreatConnect Connector | version %s" % version.__version__)
        logger.debug("starting continuous feed retrieval thread")
        work_thread = threading.Thread(target=self.perform_continuous_feed_retrieval)
        work_thread.setDaemon(True)
        work_thread.start()

        logger.debug("starting flask")
        self.serve()

    def validate_config(self):
        if self.validated_config:
            return True
        
        self.validated_config = True
        logger.debug("Validating configuration file ...")

        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            logger.error("Configuration does not contain a [bridge] section")
            return False
        
        tc_options = self.options.get('threatconnect', {})
        if not tc_options:
            logger.error("configuration does not contain a [threatconnect] section or section is empty.")
            return False
        
        try:
            self.tc_config = ThreatConnectConfig(**tc_options)
        except Exception as e:
            logger.error(e)
            return False

        if 'debug' in self.options:
            self.debug = True if self.options['debug'] in ['1', 't', 'T', 'True', 'true'] else False
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

        self.pretty_print_json = self.options.get('pretty_print_json', False) in ['1', 't', 'T', 'True', 'true']

        opts = self.bridge_options
        config_valid = True
        msgs = []

        item = 'listener_port'
        if not (item in opts and opts[item].isdigit() and 0 < int(opts[item]) <= 65535):
            msgs.append('the config option listener_port is required and must be a valid port number')
            config_valid = False
        else:
            opts[item] = int(opts[item])

        item = 'listener_address'
        if not (item in opts and opts[item]):
            msgs.append('the config option listener_address is required and cannot be empty')
            config_valid = False

        item = 'feed_retrieval_minutes'
        if not (item in opts and opts[item].isdigit() and 0 < int(opts[item])):
            msgs.append('the config option feed_retrieval_minutes is required and must be greater than 1')
            config_valid = False
        else:
            opts[item] = int(opts[item])

        # Create a cbapi instance
        server_url = self.get_config_string("carbonblack_server_url", "https://127.0.0.1")
        server_token = self.get_config_string("carbonblack_server_token", "")
        try:
            self.cb = CbResponseAPI(url=server_url,
                                    token=server_token,
                                    ssl_verify=False,
                                    integration_name=self.integration_name)
            self.cb.info()
        except Exception:
            logger.error(traceback.format_exc())
            return False

        if not config_valid:
            for msg in msgs:
                sys.stderr.write("%s\n" % msg)
                logger.error(msg)
            return False
        else:
            return True

    def perform_continuous_feed_retrieval(self, loop_forever=True):
        try:
            self.validate_config()

            opts = self.bridge_options

            folder = self.bridge_options.get("cache_folder", "./")
            cbint.utils.filesystem.ensure_directory_exists(folder)

            while True:
                logger.debug("Starting retrieval iteration")
                errored = True

                try:
                    start = timer()
                    tc = ThreatConnectDriver(self.tc_config)
                    reports = tc.generate_reports()
                    logger.debug("Retrieved reports ({0:.3f} seconds).".format(timer() - start))
                    if reports:
                        write_start = timer()
                        # Instead of rewriting the cache file directly, we're writing to a temporary file
                        # and then moving it onto the cache file so that we don't have a situation where
                        # the cache file is only partially written and corrupt or empty.
                        with open(os.path.join(folder, "reports.cache_new"), "w") as f:
                            if self.pretty_print_json:
                                f.write(json.dumps(reports, cls=SetEncoder, indent=2))
                            else:
                                f.write(json.dumps(reports, cls=SetEncoder))
                        # This is a quick operation that will not leave the file in an invalid state.
                        shutil.move(os.path.join(folder, "reports.cache_new"), os.path.join(folder, "reports.cache"))
                        logger.debug("Finished writing reports to cache ({0:.3f} seconds).".format(timer() - write_start))
                    with self.feed_lock:
                        if reports:
                            self.feed["reports"] = reports
                        self.last_successful_sync.stamp()
                    logger.info("Successfully retrieved data at {0} ({1:.3f} seconds total)".format(
                        self.last_successful_sync, timer() - start))
                    errored = False

                    self._sync_cb_feed()

                except Exception as e:
                    logger.exception("Error occurred while attempting to retrieve feed: {0}".format(e))

                self.last_sync.stamp()
                logger.debug("Feed report retrieval completed{0}.".format(" (Errored)" if errored else ""))

                if not loop_forever:
                    return self.flask_feed.generate_json_feed(self.feed).data
                
                # Full sleep interval is taken between feed retrieval work.
                time.sleep(opts.get('feed_retrieval_minutes') * 60)
        
        except Exception:
            # If an exception makes us exit then log what we can for our own sake
            logger.fatal("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality! ")
            logger.fatal("Fatal Error Encountered:\n %s" % traceback.format_exc())
            sys.stderr.write("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality!\n")
            sys.stderr.write("Fatal Error Encountered:\n %s\n" % traceback.format_exc())
            sys.exit(3)

        # If we somehow get here the function is going to exit.
        # This is not normal so we LOUDLY log the fact
        logger.fatal("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality!")

    def _sync_cb_feed(self):
        opts = self.bridge_options

        if "skip_cb_sync" in opts:
            return
        
        try:
            feeds = get_object_by_name_or_id(self.cb, Feed, name=self.feed_name)
        except Exception as e:
            logger.error(e.message)
            feeds = None

        if not feeds:
            logger.info("Feed {} was not found, so we are going to create it".format(self.feed_name))
            f = self.cb.create(Feed)
            f.feed_url = "http://{0}:{1}/threatconnect/json".format(
                self.bridge_options.get('feed_host', '127.0.0.1'),
                self.bridge_options.get('listener_port', '6100'))
            f.enabled = True
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    logger.info("Could not add feed:")
                    logger.info(
                        " Received error code 500 from server. "
                        "This is usually because the server cannot retrieve the feed.")
                    logger.info(
                        " Check to ensure the Cb server has network connectivity and the credentials are correct.")
                else:
                    logger.info("Could not add feed: {0:s}".format(str(se)))
            except Exception as e:
                logger.info("Could not add feed: {0:s}".format(str(e)))
            else:
                logger.info("Feed data: {0:s}".format(str(f)))
                logger.info("Added feed. New feed ID is {0:d}".format(f.id))
                f.synchronize(False)

        elif len(feeds) > 1:
            logger.warning("Multiple feeds found, selecting Feed id {}".format(feeds[0].id))

        elif feeds:
            feed_id = feeds[0].id
            logger.info("Feed {} was found as Feed ID {}".format(self.feed_name, feed_id))
            feeds[0].synchronize(False)
