#
# Copyright 2019 CarbonBlack, Inc
#

import os
import sys
import simplejson

sys.modules['json'] = simplejson
import time
from time import gmtime, strftime
import logging
from logging.handlers import RotatingFileHandler
import threading
from . import version

import cbint.utils.feed
import cbint.utils.flaskfeed
import cbint.utils.cbserver
import cbint.utils.filesystem
from cbint.utils.daemon import CbIntegrationDaemon
import flask
import gc
from timeit import default_timer as timer

from cbopensource.driver.threatconnect import ThreatConnectConfig, ThreatConnectDriver
import traceback

from cbapi.response import CbResponseAPI, Feed
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.errors import ServerError, ApiError

from .feed_cache import FeedCache

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


class CarbonBlackThreatConnectBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile, logfile=None, pidfile=None, debug=False):

        CbIntegrationDaemon.__init__(self, name, configfile=configfile, logfile=logfile, pidfile=pidfile, debug=debug)
        template_folder = "/usr/share/cb/integrations/cb-threatconnect-connector/content"

        # noinspection PyUnresolvedReferences
        self.flask_feed = cbint.utils.flaskfeed.FlaskFeed(__name__, False, template_folder)
        self.bridge_options = {}
        self.tc_config = {}
        self.api_urns = {}
        self.validated_config = False
        self.cb = None
        self.sync_needed = False
        self.feed_name = "threatconnectintegration"
        self.display_name = "ThreatConnect"
        self.directory = template_folder
        self.cb_image_path = "/carbonblack.png"
        self.integration_image_path = "/threatconnect.png"
        self.integration_image_small_path = "/threatconnect-small.png"
        self.json_feed_path = "/threatconnect/json"
        self.feed_lock = threading.RLock()
        self.logfile = logfile
        self.debug = debug
        self.pretty_print_json = False
        self._log_handler = None
        self.logger = logger
        self.skip_cb_sync = False
        self.execution_path = os.getcwd()
        self.cache_path = "/usr/share/cb/integrations/cb-threatconnect-connector/cache"
        self.feed_cache = FeedCache(self, self.cache_path, self.feed_lock)

        self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])

        self.initialize_logging()

        logger.debug("generating feed metadata")

        with self.feed_cache.lock:
            self.last_sync = TimeStamp()
            self.last_successful_sync = TimeStamp()
            self.feed_ready = False

    def initialize_logging(self):
        if not self.logfile:
            log_path = "/var/log/cb/integrations/%s/" % self.name
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = "%s%s.log" % (log_path, self.name)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        root_logger.handlers = []

        rlh = RotatingFileHandler(self.logfile, maxBytes=10 * 1024 * 1024, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s - %(levelname)-7s - %(module)s - %(message)s"))
        self._log_handler = rlh
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
        self._report_memory_usage("hosting")
        return flask.send_from_directory(self.feed_cache.location, self.feed_cache.file_name,
                                         mimetype='application/json')

    def handle_html_feed_request(self):
        feed = self.feed_cache.read()
        if not feed:
            return flask.Response(status=404)

        html = self.flask_feed.generate_html_feed(feed, self.display_name)
        del feed
        gc.collect()
        return html

    def handle_index_request(self):
        with self.feed_lock:
            index = self.flask_feed.generate_html_index(self.feed_cache.generate_feed(), self.bridge_options,
                                                        self.display_name, self.cb_image_path,
                                                        self.integration_image_path, self.json_feed_path,
                                                        str(self.last_sync))
        return index

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self.directory, self.cb_image_path))

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" %
                                                                  (self.directory, self.integration_image_path))

    def on_starting(self):
        self.feed_cache.verify()
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
        msgs = []

        if self.validated_config:
            return True

        self.validated_config = True
        logger.debug("Validating configuration file ...")

        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            sys.stderr.write("Configuration does not contain a [bridge] section\n")
            logger.error("Configuration does not contain a [bridge] section")
            return False

        self.debug = self.bridge_options.get('debug', 'F') in ['1', 't', 'T', 'True', 'true']
        log_level = self.bridge_options.get('log_level', 'INFO').upper()
        log_level = log_level if log_level in ["INFO", "WARNING", "DEBUG", "ERROR"] else "INFO"
        self.logger.setLevel(logging.DEBUG if self.debug else logging.getLevelName(log_level))

        try:
            log_file_size = int(self.bridge_options.get('log_file_size', 10 * 1024 * 1024))
            if log_file_size < 0:
                raise ValueError("log_file_size must be a positive number.")
            self._log_handler.maxBytes = log_file_size
        except ValueError:
            msgs.append("log_file_size must be a positive number.")

        tc_options = self.options.get('threatconnect', {})
        if not tc_options:
            sys.stderr.write("Configuration does not contain a [threatconnect] section or section is empty.\n")
            logger.error("configuration does not contain a [threatconnect] section or section is empty.")
            return False
        try:
            self.tc_config = ThreatConnectConfig(**tc_options)
        except Exception as e:
            msgs.append(str(e))

        self.pretty_print_json = self.bridge_options.get('pretty_print_json', 'F') in ['1', 't', 'T', 'True', 'true']

        ca_file = os.environ.get("REQUESTS_CA_BUNDLE", None)
        if ca_file:
            logger.info("Using CA Cert file: {0}".format(ca_file))
        else:
            logger.info("No CA Cert file found.")

        opts = self.bridge_options

        cache_path = self.bridge_options.get("cache_folder", self.cache_path)
        if not cache_path.startswith('/'):
            cache_path = os.path.join(self.execution_path, cache_path)
        if cache_path != self.cache_path:
            self.cache_path = cache_path
            del self.feed_cache
            self.feed_cache = FeedCache(self, self.cache_path, self.feed_lock)

        item = 'listener_port'
        if not (item in opts and opts[item].isdigit() and 0 < int(opts[item]) <= 65535):
            msgs.append('the config option listener_port is required and must be a valid port number')
        else:
            opts[item] = int(opts[item])

        item = 'listener_address'
        if not (item in opts and opts[item]):
            msgs.append('the config option listener_address is required and cannot be empty')

        item = 'feed_retrieval_minutes'
        if not (item in opts and opts[item].isdigit() and 0 < int(opts[item])):
            msgs.append('the config option feed_retrieval_minutes is required and must be greater than 1')
        else:
            opts[item] = int(opts[item])

        # Create a cbapi instance
        self.skip_cb_sync = opts.get('skip_cb_sync', 'F').lower() in ['1', 't', 'true']

        if not self.skip_cb_sync:
            server_url = self.get_config_string("carbonblack_server_url", "https://127.0.0.1")
            server_token = self.get_config_string("carbonblack_server_token", "")

            try:
                self.cb = CbResponseAPI(url=server_url,
                                        token=server_token,
                                        ssl_verify=False,
                                        integration_name=self.integration_name)
                self.cb.info()
            except ApiError:
                msgs.append("Could not connect to Cb Response server: {0}".format(server_url))
            except Exception as e:
                msgs.append("Failed to connect to Cb Response server {0} with error: {1}".format(server_url, e))

        if msgs:
            for msg in msgs:
                sys.stderr.write("Error: %s\n" % msg)
                logger.error(msg)
            return False

        return True

    # noinspection PyUnusedLocal
    @staticmethod
    def _report_memory_usage(title):
        gc.collect()
        # m = psutil.Process().memory_info()
        # print("({:<10}) Memory Usage: [{:14,}] [{:14,}] [{:14,}]".format(title, m.rss, m.data, m.vms))

    def _retrieve_reports(self):
        start = timer()
        self._report_memory_usage("reading")
        tc = ThreatConnectDriver(self.tc_config)
        reports = tc.generate_reports()
        self._report_memory_usage("generated")
        logger.debug("Retrieved reports ({0:.3f} seconds).".format(timer() - start))
        if reports:
            # Instead of rewriting the cache file directly, we're writing to a temporary file
            # and then moving it onto the cache file so that we don't have a situation where
            # the cache file is only partially written and corrupt or empty.
            if self.feed_cache.write_reports(reports):
                self.last_successful_sync.stamp()
                del reports
                logger.info("Successfully retrieved data at {0} ({1:.3f} seconds total)".format(
                    self.last_successful_sync, timer() - start))
                self._report_memory_usage("saved")
                return True
            else:
                logger.warning("Failed to retrieve data at {0} ({1:.3f} seconds total)".format(
                    TimeStamp(True), timer() - start))
        return False

    def perform_continuous_feed_retrieval(self, loop_forever=True):
        # noinspection PyBroadException
        try:
            self.validate_config()

            opts = self.bridge_options
            cbint.utils.filesystem.ensure_directory_exists(self.cache_path)

            while True:
                logger.info("Starting feed retrieval.")
                errored = True

                try:
                    if self._retrieve_reports():
                        self._sync_cb_feed()
                        errored = False
                except Exception as e:
                    logger.exception("Error occurred while attempting to retrieve feed: {0}".format(e))
                gc.collect()

                self.last_sync.stamp()
                logger.debug("Feed report retrieval completed{0}.".format(" (Errored)" if errored else ""))

                if not loop_forever:
                    return self.feed_cache.read(as_text=True)

                # Full sleep interval is taken between feed retrieval work.
                time.sleep(opts.get('feed_retrieval_minutes') * 60)

        except Exception:
            # If an exception makes us exit then log what we can for our own sake
            logger.fatal("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality! ")
            logger.fatal("Fatal Error Encountered:\n %s" % traceback.format_exc())
            sys.stderr.write("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality!\n")
            sys.stderr.write("Fatal Error Encountered:\n %s\n" % traceback.format_exc())
            sys.exit(3)

    def _sync_cb_feed(self):
        if self.skip_cb_sync:
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
