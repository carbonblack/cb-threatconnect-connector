import logging
import os
import sys

_logger = logging.getLogger(__name__)


class Config(object):
    # noinspection PyUnusedName
    feed_name = "threatconnectintegration"
    # noinspection PyUnusedName
    display_name = "ThreatConnect"
    cb_image_path = "/carbonblack.png"
    integration_image_path = "/threatconnect.png"
    # noinspection PyUnusedName
    integration_image_small_path = "/threatconnect-small.png"
    json_feed_path = "/threatconnect/json"
    directory = "/usr/share/cb/integrations/cb-threatconnect-connector/content"

    def __init__(self, config_options):
        self._options = config_options
        self._errors = []
        self.debug = self._get_boolean('debug')
        self.log_level = self._get_string('log_level', "INFO", valid=["DEBUG", "INFO", "WARNING", "ERROR"],
                                          coerce=True, to_upper=True)
        self.log_file_size = self._get_int('log_file_size', 10 * 1024 * 1024,
                                           verify_func=lambda x: x > 0, requirement_message="positive")
        self.pretty_print_json = self._get_boolean('pretty_print_json')
        self.multi_core = self._get_boolean('multi_core', True)
        self.use_feed_stream = self._get_string('feed_save_mode', 'STREAM',
                                                valid=['STREAM', 'BULK'], to_upper=True) == 'STREAM'
        self.cache_path = self._get_string('cache_folder',
                                           "/usr/share/cb/integrations/cb-threatconnect-connector/cache")
        self.listen_port = self._get_int('listener_port', required=True, verify_func=lambda x: 0 < x <= 65535,
                                         requirement_message="a valid port number")
        self.listen_address = self._get_string('listener_address', "0.0.0.0")
        self.host_address = self._get_string('host_address', "127.0.0.1")
        # noinspection PyTypeChecker
        self.https_proxy = self._get_string('https_proxy', None)
        self.feed_retrieval_minutes = self._get_int('feed_retrieval_minutes', required=True,
                                                    verify_func=lambda x: x > 0, requirement_message="greater than 1")
        self.skip_cb_sync = self._get_boolean('skip_cb_sync', False)
        self.server_url = self._get_string("carbonblack_server_url", "https://127.0.0.1")
        self.server_token = self._get_string("carbonblack_server_token", required=not self.skip_cb_sync, hidden=True)

        if not self.cache_path.startswith('/'):
            self.cache_path = os.path.join(os.getcwd(), self.cache_path)

    def __getitem__(self, key):
        return self._options[key]

    def get(self, key, default=None):
        return self._options.get(key, default)

    @property
    def options(self):
        return self._options

    @property
    def errored(self):
        return len(self._errors)

    @staticmethod
    def _log_option_value(label, value, hidden=False, padding=27):
        _logger.info("{0:{2}}: {1}".format(label, len(str(value)) * '*' if hidden else value, padding))

    def _log_error(self, message):
        sys.stderr.write("Configuration Error: {}\n".format(message))
        _logger.error(message)
        self._errors.append(message)

    def _get_boolean(self, label, default=False, required=False):
        if required and (label not in self._options or not self._options[label]):
            self._log_error("The config option {} is required and must be one of [True, False, T, F, 1, 0, On, Off].".
                            format(label))
        value = self._options.get(label, 't' if default else 'f').lower() in ['t', 'true', '1', 'on']
        self._log_option_value(label, value)
        return value

    def _get_int(self, label, default=None, required=False, verify_func=None, requirement_message=""):
        error_message = "The config option {} is a required number{}.".format(
            label, " and must be {}".format(requirement_message) if requirement_message else "")
        if required and label not in self._options:
            self._log_error(error_message)
            return default
        try:
            value = self._options.get(label, str(default))
            value = int(value)
        except ValueError:
            self._log_error(error_message)
            return default
        if not verify_func(value):
            self._log_error(error_message)
            return default
        self._log_option_value(label, value)
        return value

    # noinspection PyShadowingBuiltins,PyDefaultArgument
    def _get_string(self, label, default="", required=False, valid=[], coerce=False, to_upper=False, to_lower=False,
                    hidden=False):
        error_message = "The config option {}{}{}{}".format(
            label, " is required" if required else "", " and " if required and valid else "",
            "" if not valid else "must be one of {}".format(valid))

        if required and (label not in self._options or not self._options[label]):
            self._log_error(error_message)
            return default
        value = self._options.get(label, default)
        value = value.upper() if to_upper else value.lower() if to_lower else value
        if valid and value not in valid:
            if coerce:
                value = default
            else:
                self._log_error(error_message)
                return default
        self._log_option_value(label, value, hidden)
        return value
