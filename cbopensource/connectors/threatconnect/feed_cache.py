import gc
import os
import errno
import shutil
import logging
import simplejson as json
from timeit import default_timer as timer
import threading

import cbint.utils.feed

_logger = logging.getLogger(__name__)


class FeedCache(object):
    """Manages the feed data that is cached on disk.

    Going forward, instead of keeping a feed in memory, it is now stored on disk.  This is to reduce memory
    footprint of long running process.
    """
    _feed_cache_new_file = "feed.cache_new"
    _feed_cache_file = "feed.cache"
    _reports_cache_file = "reports.cache"

    def __init__(self, config, location, lock=None):
        self._config = config
        self._location = location
        self._internal_lock = not lock
        self._lock = lock or threading.RLock()
        self._exists = False

    @property
    def lock(self):
        """This is the mutex used to access the cache file."""
        return self._lock

    @property
    def location(self):
        return self._location

    @property
    def file_name(self):
        return self._feed_cache_file

    def verify(self):
        """Checks to see if the feed cache exists on disk.
        Once it is determined to exist, it is never checked again.
        """
        if self._exists:
            return True
        self._ensure_location_exists()
        with self._lock:
            if not os.path.isfile(os.path.join(self._location, "feed.cache")):
                if os.path.isfile(os.path.join(self._location, "reports.cache")):
                    _logger.warning("Feed cache file missing.  Reading report cache to create feed.")
                    try:
                        with open(os.path.join(self._location, "reports.cache"), "r") as f:
                            reports = json.loads(f.read())
                            if self.write_reports(reports):
                                self._exists = True
                    except (IOError, OSError) as e:
                        _logger.warning("Could not read from reports cache: {0}".format(e))
                else:
                    _logger.warning("Feed cache and report cache missing.  Instance appears new.")
            else:
                self._exists = True
        gc.collect()
        return self._exists

    @property
    def exists(self):
        return self.verify()

    def generate_feed(self, reports=None):
        reports = reports or []
        feed = cbint.utils.feed.generate_feed(
            self._config.feed_name,
            summary="Threat intelligence data provided by ThreatConnect to the Carbon Black Community",
            tech_data="There are no requirements to share any data to receive this feed.",
            provider_url="http://www.threatconnect.com/",
            icon_path="{}/{}".format(self._config.directory, self._config.integration_image_path),
            small_icon_path="{}/{}".format(self._config.directory, self._config.integration_image_small_path),
            display_name=self._config.display_name,
            category="Partner")
        feed['reports'] = reports
        feed['feedinfo']['num_reports'] = len(reports)
        return feed

    def _ensure_location_exists(self):
        """This was taken from cbint.utils.filesystem to reduce the imports."""
        if not os.path.exists(self._location):
            try:
                os.makedirs(self._location)
            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    raise

    def write_reports(self, reports):
        self._ensure_location_exists()
        feed = self.generate_feed(reports)
        success = self.write_feed(feed)
        del feed
        gc.collect()
        return success

    def write_feed(self, feed):
        _logger.debug("Writing to feed cache.")
        write_start = timer()
        try:
            self._ensure_location_exists()
            with open(os.path.join(self._location, self._feed_cache_new_file), "w") as f:
                if self._config.pretty_print_json:
                    f.write(json.dumps(feed, indent=2))
                else:
                    f.write(json.dumps(feed))
                del feed
            with self._lock:
                # This is a quick operation that will not leave the file in an invalid state.
                shutil.move(os.path.join(self._location, self._feed_cache_new_file),
                            os.path.join(self._location, self._feed_cache_file))
                self._exists = True
            _logger.debug("Finished writing feed to cache ({0:.3f} seconds).".format(timer() - write_start))

        except (IOError, OSError) as e:
            _logger.error("Failed to write to feed cache: {}".format(e))
            return False
        return True

    def read(self, as_text=False):
        if not self.exists:
            return None
        with self._lock:
            try:
                with open(os.path.join(self._location, self._feed_cache_file), "r") as f:
                    return f.read() if as_text else json.loads(f.read())
            except (IOError, OSError) as e:
                _logger.exception("Could not read from feed cache: {0}".format(e))
        return None

    def __del__(self):
        if self._internal_lock:
            del self._lock
        del self._config
        del self._location
