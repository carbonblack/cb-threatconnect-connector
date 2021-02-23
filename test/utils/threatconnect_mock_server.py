__author__ = "Zachary Estep"
import logging
import os

try:
    import simplejson as json
except ImportError:
    import json

from flask import Flask, request, make_response, Response

from .generate_test_data import get_random_hex, get_random_fqdn, get_random_ip


def get_mocked_server(path):
        mocked_tc_server = Flask('threatconnect')

        @mocked_tc_server.route("/api/v2/types/indicatorTypes")
        def tc_indicator_types():
            response = {
                "status": "Success",
                "data": {
                    "resultCount": 3,
                    "indicatorType": [
                        {
                            "name": "Address",
                            "custom": "false",
                            "parsable": "true",
                            "apiBranch": "addresses",
                            "apiEntity": "address"
                        },
                        {
                            "name": "File",
                            "custom": "false",
                            "parsable": "true",
                            "apiBranch": "files",
                            "apiEntity": "file"
                        },
                        {
                            "name": "Host",
                            "custom": "false",
                            "parsable": "true",
                            "apiBranch": "hosts",
                            "apiEntity": "host"
                        },
                    ]
                }
            }
            return json.dumps(response)

        @mocked_tc_server.route("/api/v2/owners")
        def tc_owners():
            response = {
                "status": "Success",
                "data": {
                    "resultCount": 2,
                    "owner": [
                        {
                            "id": 1,
                            "name": "Example Organization",
                            "type": "Organization"
                        },
                        {
                            "id": 2,
                            "name": "Common Community",
                            "type": "Community"
                        },
                        {
                            "id": 3,
                            "name": "Carbon Black",
                            "type": "Organization"
                        }
                    ]
                }
            }
            return json.dumps(response)

        @mocked_tc_server.route("/api/v2/indicators/<type>")
        def tc_indicators(type):

            response = {
                "status": "Success",
                "data": {
                    "resultCount": 2,
                }
            }

            payload = {}

            if type == "hosts":
                payload = {"host": [
                    {
                        "id": "54321",
                        "ownerName": "Example Organization",
                        "dateAdded": "2017-07-13T17:50:17",
                        "lastModified": "2017-07-19T17:53:50Z",
                        "rating": 3,
                        "threatAssessConfidence": 50,
                        "webLink": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=phish%40example.com&owner=Example+Organization",
                        "hostName": "hostname.com"
                    },
                    {
                        "id": "54322",
                        "ownerName": "Example Organization",
                        "dateAdded": "2017-07-13T17:51:17",
                        "lastModified": "2017-07-19T17:53:49Z",
                        "rating": 3,
                        "threatAssessConfidence": 50,
                        "webLink": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=bad%40gmail.com&owner=Example+Organization",
                        "hostName": "hostname.com"
                    }
                ]}
            elif type == "files":
                payload = {"file": [
                    {
                        "id": "54321",
                        "ownerName": "Example Organization",
                        "dateAdded": "2017-07-13T17:50:17",
                        "lastModified": "2017-07-19T17:53:50Z",
                        "rating": 3,
                        "threatAssessConfidence": 50,
                        "webLink": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=phish%40example.com&owner=Example+Organization",
                        "md5": get_random_hex(32)
                    },
                    {
                        "id": "54322",
                        "ownerName": "Example Organization",
                        "dateAdded": "2017-07-13T17:51:17",
                        "lastModified": "2017-07-19T17:53:49Z",
                        "rating": 3,
                        "threatAssessConfidence": 50,
                        "webLink": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=bad%40gmail.com&owner=Example+Organization",
                        "md5": get_random_hex(32)
                    }
                ]}
            else:
                payload = {"address": [
                    {
                        "id": "54321",
                        "ownerName": "Example Organization",
                        "dateAdded": "2017-07-13T17:50:17",
                        "lastModified": "2017-07-19T17:53:50Z",
                        "rating": 3,
                        "threatAssessConfidence": 50,
                        "webLink": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=phish%40example.com&owner=Example+Organization",
                        "ip": get_random_ip()
                    },
                    {
                        "id": "54322",
                        "ownerName": "Example Organization",
                        "dateAdded": "2017-07-13T17:51:17",
                        "lastModified": "2017-07-19T17:53:49Z",
                        "rating": 3,
                        "threatAssessConfidence": 50,
                        "webLink": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=bad%40gmail.com&owner=Example+Organization",
                        "ip": get_random_ip()
                    }
                ]}
            response['data'].update(payload)
            return json.dumps(response)
        return mocked_tc_server



if __name__ == '__main__':
    mydir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(os.path.join(mydir, '..', 'data'))

    mock_server = get_mocked_server(data_dir)
    mock_server.run('127.0.0.1', 7982, debug=True)
