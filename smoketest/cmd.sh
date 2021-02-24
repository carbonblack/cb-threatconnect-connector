#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo Error: Missing rpm file location parameter.  Ex: ./run_smoketest.sh path/to/rpm
  exit 1
fi

RPM_FILE=$(find "$1" -name "*.rpm" -print -quit)

SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl.py"
if [[ "$(cat /etc/redhat-release)" == *"release 8"* ]]; then
  SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl3.py"
fi

echo Adding cb user
groupadd cb --gid 8300 && \
useradd --shell /sbin/nologin --gid cb --comment "Service account for VMware Carbon Black EDR" -M cb

echo Running smoke test on file: "$RPM_FILE"

rpm -ivh "$RPM_FILE"

cp $2/connector.conf /etc/cb/integrations/threatconnect/connector.conf
cd $2/../test ; FLASK_APP=smoke_test_server.py python3.8 -m flask run --cert=adhoc &
echo Starting service...
service cb-threatconnect-connector start
sleep 5
filepath='/usr/share/cb/integrations/cb-threatconnect-connector/cache/feed.cache'
if [ -n "$(find "$filepath" -prune -size +10000c)" ]; then
    echo "threat connect connector working ok!"
else
    echo "threat connect connector not working correctly - exiting"
    exit 1
fi

service cb-threatconnect-connector stop
yum -y remove python-cb-threatconnect-connector
