#
# Copyright 2013 CarbonBlack, Inc
#
import time
import requests
import base64
import hashlib
import hmac


class ConnectionException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ThreatConnectFeedGenerator(object):
    def __init__(self, api_key, secret_key, url, urns):
        self.URNs = urns
        self.API_KEY = api_key
        self.SECRET_KEY = secret_key
        self.URL = url

    def generate_headers(self, verb, path):
        timestamp = int(time.time())
        signature = "%s:%s:%d" % (path, verb, timestamp)
        hmac_signature = hmac.new(self.SECRET_KEY, signature, digestmod=hashlib.sha256).digest()
        authorization = 'TC %d:%s' % (self.API_KEY, base64.b64encode(hmac_signature))
        return {'Timestamp': timestamp, 'Authorization': authorization}

    def parse_iocs(self, rows):
        # Array to hold the report containing all the individual records
        reports = []
        # List of IOC types Cb is able to tag
        ioc_types = ['File', 'Address', 'Host']

        # Traverse all the rows in the JSON structure returned by the API
        for row in rows:
            # If it is not an IOC I'm capable of processing just skip it.
            if not row.get('type') in ioc_types:
                continue
            # I'm using the confidence score as the Cb score but some IOCs do not have a
            # confidence score and the max value of a confidence score can be 100.  So as
            # a precaution, I make any score greater than 100 equal 100 and default all
            # null values to 0.
            score = row.get('confidence', 0)
            score = min(score, 100)

            # Many entries are missing a description so I placed this here to default them
            # to the IOC value in the absence of a description.
            title = row.get('description', None)
            if not title:
                title = row.get('summary')
            fields = {'iocs': {},
                      'id': row.get('id'),
                      'link': row.get('webLink', ''),
                      'title': title,
                      'score': score,
                      'timestamp': int(time.mktime(time.gmtime())),
                      }
            # The next few lines are designed to insert the Cb supported IOCs into the record.
            if row.get('type') == "File":
                fields['iocs']['md5'] = [row.get('summary')[:32]]
            elif row.get('type') == "Address":
                fields['iocs']['ipv4'] = [row.get('summary')]
            elif row.get('type') == "Host":
                fields['iocs']['dns'] = [row.get('summary')]
            reports.append(fields)
        return reports

    def get_data(self, urn):
        headers = self.generate_headers('GET', urn)
        uri = self.URL + urn
        try:
            resp = requests.get(uri, headers=headers)
        except requests.exceptions.SSLError:
            raise ConnectionException("Requests failed to establish SSL connection to %s)" % uri)
        except requests.exceptions.ConnectionError as e:
            raise ConnectionException("Connection Error (%s) %s " % (uri, e.args[0]))
        if resp.status_code != 200:
            raise ConnectionException("HTTP %s - %s (%s)" % (str(resp.status_code), resp.reason, uri))
        reports = resp.json()
        if "data" not in reports:
            raise ConnectionException(str(reports))
        return reports

    def get_threatconnect_iocs(self):
        all_parsed_rows = []
        for key, urn in self.URNs:
            # Pull back a single record to get the total number of IOCs
            reports = self.get_data("{0:s}&resultStart=0&resultLimit=1".format(urn))
            records = int(reports['data']['resultCount'])
            # Ensure the community has records before we attempt to process.
            if not records:
                continue

            remaining_records = records
            start_record = 0

            print "total records = {0:d}".format(records)
            while remaining_records:
                # Pull all records per a community, max of 200 per call
                current_query = min(remaining_records, 200)

                reports = self.get_data("{0:s}&resultStart={1:d}&resultLimit={2:d}".format(urn, start_record,
                                                                                           current_query))
                parsed_rows = self.parse_iocs(reports.get('data').get('indicator'))
                all_parsed_rows += parsed_rows
                start_record += current_query
                remaining_records -= current_query

        return all_parsed_rows

