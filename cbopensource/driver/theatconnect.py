from enum import Enum
import logging
import tcex
from tcex import tcex_logger
import sys
from datetime import datetime
import time
import urllib

_logger = logging.getLogger(__name__)


class _Empty:
    """This is an empty class to create an empty object used by _fixed_format for the self._style fix."""
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
    """Represents an IOC Type that is supported by the configuration.

    To add more supported types, they just need to be added here with a value that is fully capitalized.

    File -> Pulls in hashes in either md5 or sha256 that represent files.
    Address -> Pulls in network addresses in either ipv4 or ipv6 form.
    Host -> Pulls in network names including domain names.
    """

    File = "FILE"
    Address = "ADDRESS"
    Host = "HOST"


class _TcIndicator(object):
    def __init__(self, indicator, source, ioc_type, key, value):
        self._indicator = indicator
        self._source = source
        self._ioc_type = ioc_type
        self._key = key
        self._value = value

    @property
    def id(self):
        return str(self._indicator['id'])

    @property
    def score(self):
        return int(self.rating * 20)

    @property
    def rating(self):
        return int(max(0, min(5, self._indicator.get('rating', 0))))

    @property
    def source(self):
        return self._source

    @property
    def link(self):
        return self._indicator['webLink']

    @property
    def tags(self):
        return [tag['name'] for tag in self._indicator.get('tag', [])]

    @property
    def description(self):
        return self._indicator.get('description', "")

    @property
    def timestamp(self):
        dt = datetime.strptime(self._indicator['dateAdded'], "%Y-%m-%dT%H:%M:%SZ")
        return int((time.mktime(dt.timetuple()) + dt.microsecond/1000000.0))

    @property
    def ioc_type(self):
        return self._ioc_type

    @property
    def key(self):
        return self._key

    @property
    def value(self):
        return self._value


class IocFactory(object):
    _ioc_map = {}

    def __str__(self):
        return self._name

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

    @classmethod
    def filter_ioc(cls, indicator, filters):
        if filters:
            if indicator.value in filters:
                _logger.debug("{0} IOC with value {1} was filtered.".format(cls._name, indicator.value))
                return None
        return indicator

    def __repr__(self):
        return "Ioc:{0}".format(self.__str__())


class AddressIoc(IocFactory):
    _name = "Address"

    @classmethod
    def create(cls, indicator, source, config):
        value = indicator.get('ip', None)
        if not value:
            return None
        return cls.filter_ioc(_TcIndicator(indicator, source, IocType.Address,
                                           'ipv6' if ":" in value else 'ipv4', value), config.filtered_ips)


class FileIoc(IocFactory):
    _name = "File"

    @classmethod
    def create(cls, indicator, source, config):
        key = 'md5' if 'md5' in indicator else 'sha256'
        value = indicator.get(key, None)
        if not value:
            return None
        return cls.filter_ioc(_TcIndicator(indicator, source, IocType.File, key, value),
                              config.filtered_hashes)


class HostIoc(IocFactory):
    _name = "Host"

    @classmethod
    def create(cls, indicator, source, config):
        value = indicator.get('hostName', None)
        if not value:
            return None
        return cls.filter_ioc(_TcIndicator(indicator, source, IocType.Host, 'dns', value),
                              config.filtered_hosts)


IocFactory._ioc_map = {IocType.File: FileIoc(),
                       IocType.Address: AddressIoc(),
                       IocType.Host: HostIoc()}


class IocGrouping(Enum):
    Condensed = "CONDENSED"
    MaxCondensed = "MAXCONDENSED"
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
        self._values = [] if self._all else [s.strip() for s in sources.split(",")]
    
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
        return str(key) in self._values


class ThreatConnectConfig(object):
    def __init__(self,
                 sources="*",
                 url=None,
                 web_url=None,
                 api_key=None,
                 secret_key=None,
                 filtered_ips=None,
                 filtered_hashes=None,
                 filtered_hosts=None,
                 ioc_min_rating=1,
                 ioc_types=None,
                 ioc_grouping=None,
                 max_reports=0,
                 default_org=None):
        if not url:
            raise ValueError("Invalid configuration option 'url' - option missing.")
        if not web_url:
            raise ValueError("Invalid configuration option 'web_url' - option missing.")
        if not api_key:
            raise ValueError("Invalid configuration option 'api_key' - option missing.")
        if not secret_key:
            raise ValueError("Invalid configuration option 'secret_key' - option missing.")
        try:
            ioc_min_rating = int(ioc_min_rating)
            if ioc_min_rating < 0 or ioc_min_rating > 5:
                raise ValueError(
                    "Invalid configuration option 'ioc_min_rating' - value must be a number between 0 and 5.")
        except ValueError:
            raise ValueError("Invalid configuration option 'ioc_min_rating' - value must be a number between 0 and 5.")

        self.sources = _Sources(sources)
        self.url = url.strip("/")
        self.web_url = web_url.strip("/")
        self.api_key = api_key
        self.secret_key = secret_key
        self.filtered_ips_file = filtered_ips
        self.filtered_hashes_file = filtered_hashes
        self.filtered_hosts_file = filtered_hosts
        self.filtered_ips = self._read_filter_file(filtered_ips)
        self.filtered_hashes = self._read_filter_file(filtered_hashes)
        self.filtered_hosts = self._read_filter_file(filtered_hosts)
        self.ioc_min_rating = max(0, min(5, ioc_min_rating))
        self.ioc_types = IocFactory.from_text_to_list(ioc_types, all_if_none=True)
        self.ioc_grouping = IocGrouping.from_text(ioc_grouping, default=IocGrouping.Expanded)
        self.max_reports = int(max_reports)
        self.default_org = default_org.strip()

        self._log_config()
    
    @staticmethod
    def _log_entry(title, value, padding=20):
        _logger.info("{0:{2}}: {1}".format(title, value, padding))
    
    def _log_config(self):
        _logger.info("ThreatConnect Driver configuration loaded.")
        self._log_entry("Sources", self.sources)
        self._log_entry("Url", self.url)
        self._log_entry("Web Url", self.web_url)
        self._log_entry("API Key", self.api_key)
        self._log_entry("Secret Key", "*" * len(self.secret_key))
        self._log_entry("Default Org", self.default_org)
        self._log_entry("Filtered IP File", self.filtered_ips_file)
        self._log_entry("Filtered IPs", len(self.filtered_ips))
        self._log_entry("Filtered Hash File", self.filtered_hashes_file)
        self._log_entry("Filtered Hashes", len(self.filtered_hashes))
        self._log_entry("Filtered Host File", self.filtered_hosts_file)
        self._log_entry("Filtered Hosts", len(self.filtered_hosts))
        self._log_entry("IOC Minimum Rating", self.ioc_min_rating)
        self._log_entry("IOC Types", self.ioc_types)
        self._log_entry("IOC Grouping", self.ioc_grouping)
        self._log_entry("Max Reports", self.max_reports or "Disabled")

    def _read_filter_file(self, filter_file):
        if not filter_file:
            return set()
        try:
            with open(filter_file, "r") as f:
                return set(f.readlines())
        except (OSError, IOError) as e:
            raise ValueError("Invalid filter file {0}: {1}".format(filter_file, e))


class _TcSource(object):
    def __init__(self, raw_source):
        self._source = raw_source
        self._id = int(raw_source["id"])
        self._name = raw_source["name"]

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    def __str__(self):
        return self._name

    def __repr__(self):
        return self._name

    def __eq__(self, other):
        return str(other) == str(self)

    def generate_id(self, score):
        # Moving the id over 8 bits to make room for a decimal up to 256 though we only need it up to 100
        generated_id = (self._id << 8) | score
        _logger.debug("Generating id for source [{0}] with a score of {1}: {2}".format(self._name, score, generated_id))
        return generated_id


def _TcSources(client):
    try:
        owners = [_TcSource(o) for o in client().ti.owner().many()]
        _logger.debug("Sources retrieved from threatconnect: {0}".format(owners))
        invalid = [o for o in client.config.sources.values if o not in owners]
        if invalid:
            _logger.warning("The following sources are invalid and will be skipped: {0}".format(invalid))
        for owner in owners:
            if owner.name in client.config.sources:
                yield owner
            else:
                _logger.debug(
                    "Source [{0}] in list of possible sources but not in list of requested sources.".format(owner))
    except RuntimeError:
        _logger.exception("Failed to retrieve owners from ThreatConnect connection.")
        raise


class _TcReportGenerator(object):
    _parameters = {'includes': ['additional', 'attributes', 'labels', 'tags']}

    def __init__(self, client):
        self._client = client
        self._notified_max_reports = False

    def generate_reports(self):
        count = 0
        for source in _TcSources(self._client):
            _logger.debug("Pulling IOCs from source: [{0}]".format(source))
            source_count = 0
            for ioc_type in self._client.config.ioc_types:
                try:
                    indicators = self._client().ti.indicator(indicator_type=str(ioc_type), owner=source.name)
                    for indicator in indicators.many(filters=self._filters(), params=self._parameters):
                        ioc = ioc_type.create(indicator, source, self._client.config)
                        if ioc:
                            if not self._add_to_report(ioc):
                                if not source_count:
                                    _logger.info("No IOCs imported for source: [{0}]".format(str(source)))
                                return count, len(self.reports), self.reports
                            count += 1
                            source_count += 1

                except Exception as e:
                    _logger.exception("Failed to read IOCs for source {0} and IOC type {1}".format(source, ioc_type))
            if not source_count:
                _logger.info("No IOCs found for source: [{0}]".format(source))
        return count, len(self.reports), self.reports

    def max_reports_notify(self):
        if not self._notified_max_reports:
            self._notified_max_reports = True
            _logger.warning("The maximum number of reports ({0}) has been reached.".format(
                self._client.config.max_reports))

    def _filters(self):
        filters = self._client().ti.filters()
        if self._client.config.ioc_min_rating:
            filters.add_filter("rating", ">", str(self._client.config.ioc_min_rating - 1))
        return filters


class _ExpandedReportGenerator(_TcReportGenerator):
    def __init__(self, client):
        _TcReportGenerator.__init__(self, client)
        self._reports = []

    def _add_to_report(self, indicator):
        if not indicator:
            return True
        if self._client.config.max_reports and len(self._reports) >= self._client.config.max_reports:
            self.max_reports_notify()
            return False
        report = {'iocs': {indicator.key: [indicator.value]},
                  'id': indicator.id,
                  'link': indicator.link,
                  'title': indicator.description or "{0} - {1}".format(indicator.source, indicator.id),
                  'score': indicator.score,
                  'timestamp': indicator.timestamp}
        if indicator.tags:
            report["tags"] = indicator.tags
        self._reports.append(report)
        return True

    @property
    def reports(self):
        return self._reports


class _BaseCondensedReportGenerator(_TcReportGenerator):
    def __init__(self, client):
        _TcReportGenerator.__init__(self, client)
        self._reports = []
        self._converted_sets = True

    def _get_score_list(self, indicator):
        raise NotImplementedError()

    def _generate_link(self, indicator):
        raise NotImplementedError()

    def _generate_title(self, indicator):
        raise NotImplementedError()

    def _get_report(self, indicator):
        score_list = self._get_score_list(indicator)
        report = score_list[indicator.score]
        if not report:
            if self._client.config.max_reports and len(self._reports) >= self._client.config.max_reports:
                self.max_reports_notify()
                return None
            gid = indicator.source.generate_id(indicator.score)
            report = {'iocs': {},
                      'id': gid,
                      'link': self._generate_link(indicator),
                      'title': self._generate_title(indicator),
                      'score': indicator.score,
                      'timestamp': indicator.timestamp}
            score_list[indicator.score] = report
            self._reports.append(report)
        return report

    def _add_to_report(self, indicator):
        if not indicator:
            return True
        report = self._get_report(indicator)
        if report:
            self._converted_sets = False
            iocs = report['iocs']
            ioc_list = iocs.get(indicator.key, None)
            if not ioc_list:
                ioc_list = set()
                iocs[indicator.key] = ioc_list
            ioc_list.add(indicator.value)
        return True

    @property
    def reports(self):
        if not self._converted_sets:
            for report in self._reports:
                for k, v in report["iocs"].iteritems():
                    report["iocs"][k] = list(v)
            self._converted_sets = True
        return self._reports


class _MaxCondensedReportGenerator(_BaseCondensedReportGenerator):
    def __init__(self, client):
        _BaseCondensedReportGenerator.__init__(self, client)
        self._reports_map = {}

    def _get_score_list(self, indicator):
        score_list = self._reports_map.get(indicator.source, None)
        if not score_list:
            score_list = [None] * 101  # 101 because 0 to 100 inclusive
            self._reports_map[indicator.source] = score_list
        return score_list

    def _generate_link(self, indicator):
        rating = indicator.rating
        rating = " AND rating = {0}".format(rating) if rating else ""
        url_params = {"filters": 'ownername = "{0}" AND typeName in (["Address", "File", "Host"])'
                                 '{1}'.format(indicator.source, rating),
                      "advanced": "true",
                      "intelType": "indicators"}
        return "{0}/browse/index.xhtml?{1}".format(self._client.config.web_url, urllib.urlencode(url_params))

    def _generate_title(self, indicator):
        return "{0} - {1}".format(indicator.source, indicator.score)


class _CondensedReportGenerator(_BaseCondensedReportGenerator):
    def __init__(self, client):
        _BaseCondensedReportGenerator.__init__(self, client)
        self._reports_map = {}

    def _get_score_list(self, indicator):
        type_list = self._reports_map.get(indicator.source, None)
        if not type_list:
            type_list = {}
            self._reports_map[indicator.source] = type_list

        score_list = type_list.get(indicator.ioc_type, None)
        if not score_list:
            score_list = [None] * 101  # 101 because 0 to 100 inclusive
            type_list[indicator.ioc_type] = score_list
        return score_list

    def _generate_link(self, indicator):
        rating = indicator.rating
        rating = " AND rating = {0}".format(rating) if rating else ""
        url_params = {"filters": 'ownername = "{0}" AND typeName in (["{1}"])'
                                 '{2}'.format(indicator.source, indicator.ioc_type.name, rating),
                      "advanced": "true",
                      "intelType": "indicators"}
        return "{0}/browse/index.xhtml?{1}".format(self._client.config.web_url, urllib.urlencode(url_params))

    def _generate_title(self, indicator):
        return "{0} - {1} - {2}".format(indicator.source, indicator.ioc_type.name, indicator.score)


_reportGenerators = {
    IocGrouping.Expanded: _ExpandedReportGenerator,
    IocGrouping.Condensed: _CondensedReportGenerator,
    IocGrouping.MaxCondensed: _MaxCondensedReportGenerator}


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

        ioc_count, report_count, reports = _reportGenerators[self._config.ioc_grouping](self._client).generate_reports()

        _logger.info("Retrieved {0} reports and {1} iocs.".format(report_count, ioc_count))
        return reports

    @classmethod
    def initialize(cls, config):
        cls._client = ThreatConnectClient(config)
