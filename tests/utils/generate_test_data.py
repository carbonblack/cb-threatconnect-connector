#!/usr/bin/env python

__author__ = 'jgarman'

import sys
import random
import datetime
import socket
import struct
import urllib
import json


epoch = datetime.datetime.utcfromtimestamp(0)
url_base = "http://localhost/tc/auth/indicators/details"


def get_date_string(dt):
    return datetime.datetime.strftime(dt, '%Y-%m-%dT%H:%M:%SZ')


def get_random_date(start_date, end_date):
    dt = random.randint(
        int((start_date - epoch).total_seconds()),
        int((end_date - epoch).total_seconds())
    )
    return datetime.datetime.utcfromtimestamp(dt)


def get_random_hex(len):
    return ''.join([random.choice('0123456789ABCDEF') for i in range(len)])


def get_random_ip():
        ip_address = random.randint(3232235520, 3232301055)
        ip_address = struct.pack('>I', ip_address)
        return socket.inet_ntoa(ip_address)


def get_random_fqdn():
    num_parts = random.randint(1, 4)
    tld = random.choice(['com', 'org', 'net', 'us', 'co.uk'])

    parts = random.sample(list(open('/usr/share/dict/words', 'r')), num_parts)
    fqdn = '.'.join([part.strip().lower() for part in parts]) + '.' + tld
    return fqdn


def generate_record(owner_name, id_number):
    date_added = get_random_date(datetime.datetime(2015, 1, 1), datetime.datetime.utcnow())
    last_modified = get_random_date(datetime.datetime(2015, 1, 1), datetime.datetime.utcnow())
    record_type = random.choice(['Address', 'File', 'Host', 'Unsupported'])
    url_owner_name = urllib.quote_plus(owner_name)

    record = {
        "dateAdded" : get_date_string(date_added),
        "lastModified" : get_date_string(last_modified),
        "id": id_number,
        "type": record_type,
        "ownerName": owner_name,
    }

    if record_type == 'Address':
        ip_address = get_random_ip()

        record["summary"] = ip_address
        record["webLink"] = "{0:s}/address.xhtml?address={1:s}&owner={2:s}".format(url_base, ip_address, url_owner_name)

    elif record_type == 'File':
        file_md5_hash = get_random_hex(32)
        file_sha1_hash = get_random_hex(40)
        file_sha256_hash = get_random_hex(64)

        record["summary"] = "{0:s} : {1:s} : {2:s}".format(file_md5_hash, file_sha1_hash, file_sha256_hash)
        record["webLink"] = "{0:s}/file.xhtml?file={1:s}&owner={2:s}".format(url_base, file_md5_hash, url_owner_name)

    elif record_type == 'Host':
        fqdn = get_random_fqdn()

        record["summary"] = fqdn
        record["webLink"] = "{0:s}/host.xhtml?host={1:s}&owner={2:s}".format(url_base, fqdn, url_owner_name)

    return record


def main():
    num_records = random.randint(1000, 15000)
    start_id = random.randint(0, 1000000)

    result = {
        "status": "Success",
        "data": {
            "indicator": [],
            "resultCount": num_records
        }
    }

    for i in xrange(num_records):
        result['data']['indicator'].append(generate_record("Common Community", start_id+i))

    print(json.dumps(result))


if __name__ == '__main__':
    sys.exit(main())
