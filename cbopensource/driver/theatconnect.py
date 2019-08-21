from enum import Enum
import logging
import tcex
from tcex import tcex_logger
import sys
from datetime import datetime
import time

_logger = logging.getLogger(__name__)


class _Empty:
    pass


def _fixed_format(self, record):
    """There is an exception being thrown in tcex v1.0.7.  This is an attempt to get around the exception."""

    if not hasattr(self, "_style"):
        self._style = _Empty()
        self._style._fmt = _Empty()
    # Save the original format configured by the user
    # when the logger formatter was instantiated
    format_orig = self._style._fmt

    # Replace the original format with one customized by logging level
    if record.levelno in [logging.DEBUG, logging.TRACE]:
        self._style._fmt = tcex_logger.FileHandleFormatter.trace_format
    else:
        self._style._fmt = tcex_logger.FileHandleFormatter.standard_format

    # Call the original formatter class to do the grunt work
    result = logging.Formatter.format(self, record)

    # Restore the original format configured by the user
    self._style._fmt = format_orig

    return result


tcex_logger.FileHandleFormatter.format = _fixed_format


class IocType(Enum):
    File = "FILE"
    Address = "ADDRESS"
    Host = "HOST"


class _TcIndicator(object):
    def __init__(self, indicator, source, key, value):
        self._indicator = indicator
        self._source = source
        self._key = key
        self._value = value

    @property
    def id(self):
        return str(self._indicator['id'])

    @property
    def score(self):
        return int(self._indicator['threatAssessRating'] * 20)

    @property
    def source(self):
        return self._source

    @property
    def link(self):
        return self._indicator['webLink']

    @property
    def timestamp(self):
        dt = datetime.strptime(self._indicator['dateAdded'], "%Y-%m-%dT%H:%M:%SZ")
        return int((time.mktime(dt.timetuple()) + dt.microsecond/1000000.0))

    @property
    def key(self):
        return self._key

    @property
    def value(self):
        return self._value


class IocFactory(object):
    _ioc_map = {}

    @classmethod
    def from_text(cls, text):
        return cls._ioc_map[IocType(text.strip().upper())]

    @classmethod
    def from_text_to_list(cls, text, all_if_none):
        if text:
            return [cls.from_text(t) for t in text.split(",")]
        elif all_if_none:
            return cls.All()
        return []

    @classmethod
    def all(cls):
        return cls.ioc_map.values()

    def __repr__(self):
        return "Ioc:{0}".format(self.__str__())


class AddressIoc(IocFactory):
    def __str__(self):
        return "Address"

    @staticmethod
    def create(indicator, source):
        address = indicator['ip']
        return _TcIndicator(indicator, source, 'ipv6' if ":" in address else 'ipv4', address)


class FileIoc(IocFactory):
    def __str__(self):
        return "File"

    @staticmethod
    def create(indicator, source):
        key = 'md5' if 'md5' in indicator else 'sha256'
        return _TcIndicator(indicator, source, key, indicator[key])


class HostIoc(IocFactory):
    def __str__(self):
        return "Host"

    @staticmethod
    def create(indicator, source):
        return _TcIndicator(indicator, source, 'dns', indicator['hostName'])


IocFactory._ioc_map = {IocType.File: FileIoc(),
                       IocType.Address: AddressIoc(),
                       IocType.Host: HostIoc()}


class IocGrouping(Enum):
    Condensed = "CONDENSED"
    Expanded = "EXPANDED"

    @classmethod
    def from_text(cls, text, default):
        if text:
            return cls(text.strip().upper())
        return default


class _Sources(object):
    def __init__(self, sources="*"):
        sources = sources.strip()
        self._all = sources == "*"
        self._values = () if self._all else (s.strip() for s in sources.split(","))
    
    @property
    def all(self):
        return self._all
    
    @property
    def values(self):
        return self._values

    def __str__(self):
        return "*" if self._all else str(self._values)

    def __repr__(self):
        return "Sources({0})".format(self.__str__())

    def __contains__(self, key):
        if self.all:
            return True
        return key in self._values


class ThreatConnectConfig(object):
    def __init__(self,
                 sources="*",
                 url=None,
                 api_key=None,
                 secret_key=None,
                 filtered_ips=None,
                 filtered_md5s=None,
                 filtered_hosts=None,
                 ioc_min_score=0,
                 ioc_types=None,
                 ioc_grouping=None,
                 default_org=None):
        if not url:
            raise ValueError("Invalid configuration option 'url' - option missing.")
        if not api_key:
            raise ValueError("Invalid configuration option 'api_key' - option missing.")
        if not secret_key:
            raise ValueError("Invalid configuration option 'secret_key' - option missing.")
        try:
            ioc_min_score = int(ioc_min_score)
        except ValueError:
            raise ValueError("Invalid configuration option 'ioc_min_score' - value must be a number.")

        self.sources = _Sources(sources)
        self.url = url
        self.api_key = api_key
        self.secret_key = secret_key
        self.filtered_ips = filtered_ips
        self.filtered_md5s = filtered_md5s
        self.filtered_hosts = filtered_hosts
        self.ioc_min_score = min(0, max(100, ioc_min_score))
        self.ioc_types = IocFactory.from_text_to_list(ioc_types, all_if_none=True)
        self.ioc_grouping = IocGrouping.from_text(ioc_grouping, default=IocGrouping.Expanded)
        self.default_org = default_org.strip()

        self._log_config()
    
    @staticmethod
    def _log_entry(title, value, padding=20):
        _logger.info("{0:{2}}: {1}".format(title, value, padding))
    
    def _log_config(self):
        _logger.info("ThreatConnect Driver configuration loaded.")
        self._log_entry("Sources", self.sources)
        self._log_entry("Url", self.url)
        self._log_entry("API Key", self.api_key)
        self._log_entry("Secret Key", "*" * len(self.secret_key))
        self._log_entry("Filtered IP File", self.filtered_ips)
        self._log_entry("Filtered MD5 File", self.filtered_md5s)
        self._log_entry("Filtered Host File", self.filtered_hosts)
        self._log_entry("IOC Minimum Score", self.ioc_min_score)
        self._log_entry("IOC Types", self.ioc_types)
        self._log_entry("IOC Grouping", self.ioc_grouping)


def _TcSources(client):
    try:
        for owner in client().ti.owner().many():
            owner = owner["name"]
            if owner in client.config.sources:
                yield owner
    except RuntimeError:
        _logger.exception("Failed to retrieve owners from ThreatConnect connection.")
        raise


class _TcReportGenerator(object):
    _parameters = {'includes': ['additional', 'attributes', 'labels', 'tags']}

    def __init__(self, client):
        self._client = client

    def generate_reports(self):
        for source in _TcSources(self._client):
            for ioc_type in self._client.config.ioc_types:
                try:
                    indicators = self._client().ti.indicator(indicator_type=str(ioc_type), owner=source)
                    for indicator in indicators.many(filters=self._filters(), params=self._parameters):
                        self._add_to_report(ioc_type.create(indicator, source))

                except Exception as e:
                    _logger.exception("Failed to read IOCs for source {0} and IOC type {1}".format(source, ioc_type))
        return self.reports

    def _filters(self):
        filters = self._client().ti.filters()
        if self._client.config.ioc_min_score:
            filters.add_filter("rating", ">=", self._client.config.ioc_min_score)


class _ExpandedReportGenerator(_TcReportGenerator):
    def __init__(self, client):
        _TcReportGenerator.__init__(self, client)
        self._reports = []

    def _add_to_report(self, indicator):
        report = {'iocs': {indicator.key: [indicator.value]},
                  'id': indicator.id,
                  'link': indicator.link,
                  'title': "{0}-{1}".format(indicator.source, indicator.id),
                  'score': indicator.score,
                  'timestamp': indicator.timestamp}
        self._reports.append(report)

    @property
    def reports(self):
        return self._reports


class _CondensedReportGenerator(_TcReportGenerator):
    def __init__(self, client):
        _TcReportGenerator.__init__(self, client)
        # Using both for speed and convenience
        self._reports_map = {}
        self._reports = []

    def _get_score_list(self, source):
        score_list = self._reports_map.get(source, None)
        if not score_list:
            score_list = [None] * 101  # 101 because 0 to 100 inclusive
            self._reports_map[source] = score_list
        return score_list

    def _get_report(self, indicator):
        score_list = self._get_score_list(indicator.source)
        report = score_list[indicator.score]
        if not report:
            report = {'iocs': {},
                      'id': indicator.id,
                      'link': indicator.link,
                      'title': "{0}-{1}".format(indicator.source, indicator.id),
                      'score': indicator.score,
                      'timestamp': indicator.timestamp}
            score_list[indicator.score] = report
            self._reports.append(report)
        return report

    def _add_to_report(self, indicator):
        report = self._get_report(indicator)
        iocs = report['iocs']
        ioc_list = iocs.get(indicator.key, None)
        if not ioc_list:
            ioc_list = []
            iocs[indicator.key] = ioc_list
        ioc_list.append(indicator.value)

    @property
    def reports(self):
        return self._reports


_reportGenerators = {
    IocGrouping.Expanded: _ExpandedReportGenerator,
    IocGrouping.Condensed: _CondensedReportGenerator}


class ThreatConnectClient(object):
    def __init__(self, config):
        self._config = config
        
        # The tcex library expects to be run as a command-line utility, normally within a TC Playbook.
        # For this reason, the command-line args must be replaced with tcex specific ones.
        sys.argv = [sys.argv[0],
                    "--tc_api_path", config.url,
                    "--api_access_id", config.api_key,
                    "--api_secret_key", config.secret_key]
        if config.default_org:
            sys.argv.extend(["--api_default_org", config.default_org])
        
        self._tcex = tcex.TcEx()
    
    def __call__(self):
        return self._tcex
    
    @property
    def config(self):
        return self._config


class ThreatConnectDriver(object):
    _client = None

    def __init__(self, config):
        self._config = config
    
    def generate_reports(self):
        _logger.debug("Starting report retrieval.")

        if not self._client:
            raise RuntimeError("The ThreatConnectDriver has not been initialized.")

        reports = _reportGenerators[self._config.ioc_grouping](self._client).generate_reports()

        _logger.debug("Retrieved {0} reports.".format(len(reports)))
        return reports


    @classmethod
    def initialize(cls, config):
        cls._client = ThreatConnectClient(config)
