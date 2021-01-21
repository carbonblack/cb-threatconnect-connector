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

#echo
#echo Setting up environment
#echo
#
#yum -y update systemd && \
#curl -o /usr/bin/systemctl -fSL "${SYSTEM_CTL_PATCH}" && \
#chmod +x /usr/bin/systemctl
#yum install -y initscripts
#
#echo
#echo Adding cb user
#echo
#groupadd cb --gid 8300 && \
#useradd --shell /sbin/nologin --home-dir /var/cb --gid cb --comment "Service account for VMware Carbon Black EDR" -M cb

echo
echo Running smoke test on file: "$RPM_FILE"
echo

yum install -y "$RPM_FILE"

echo
echo Starting service...
echo
sleep 9999999999
service cb-threatconnect-connector start
