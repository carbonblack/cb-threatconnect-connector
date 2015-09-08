import logging
import os

try:
    import simplejson as json
except ImportError:
    import json

from flask import Flask, request, make_response, Response


def get_mocked_server(data_directory):
    mocked_tc_server = Flask('threatconnect')
    data = json.load(open(os.path.join(data_directory, 'testdata.json'), 'rb'))

    @mocked_tc_server.route('/v1/indicators/')
    @mocked_tc_server.route('/v2/indicators/')
    def tc_indicators():
        owner = request.args.get('owner', None)
        if not owner or owner != 'Common Community':
            return Response(json.dumps({"Status": "Error"}), 404)

        result_start = int(request.args.get('resultStart', 0))
        result_count = int(request.args.get('resultLimit', 100))

        results = data['data']['indicator'][::]
        results = results[result_start:result_count+result_start]

        outdata = {"status": "Success", "data": {"resultCount": data['data']['resultCount'], "indicator": results}}

        return Response(json.dumps(outdata), mimetype='application/json')

    return mocked_tc_server


if __name__ == '__main__':
    mydir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(os.path.join(mydir, '..', 'data'))

    mock_server = get_mocked_server(data_dir)
    mock_server.run('127.0.0.1', 7982, debug=True)
