# Carbon Black - ThreatConnect Connector

Carbon Black provides integration with ThreatConnect by retrieving Indicators of
Compromise (IOCs) from specified communities. To support this integration, Carbon
Black provides an out-of-band bridge that communicates with the ThreatConnect API.

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-threatconnect-bridge
```

Once the software is installed via YUM, copy the 
`/etc/cb/integrations/cb_threatconnect_bridge/cb_threatconnect_bridge.conf.example` file to 
`/etc/cb/integrations/cb_threatconnect_bridge/cb_threatconnect_bridge.conf`.
 Edit this file and place your Carbon Black API key into the 
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Next, place the credentials for your ThreatConnect API account into the `api_key` and `secret_key` variables. The 
`api_key` variable is the numeric API identifier issued by ThreatConnect, and the `secret_key` is a long alphanumeric +
symbols secret key assigned to you. Any special characters in the secret key do not have to be escaped in the
configuration file.

Finally, add all subscribed communities from which you wish to push indicator data to Carbon Black to the `[sources]`
section of the configuration file. The configuration file includes the "CommonCommunity" community by default.

Once you have the connector configured for your API access, start the ThreatConnect service:
```
service cb-threatconnect-bridge start
```

Any errors will be logged into `/var/log/cb/integrations/carbonblack_threatconnect_bridge/carbonblack_threatconnect_bridge.log`.

## Troubleshooting

If you suspect a problem, please first look at the ThreatConnect connector logs found here: 
`/var/log/cb/integrations/carbonblack_threatconnect_bridge/carbonblack_threatconnect_bridge.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

## Contacting Bit9 Developer Relations Support

Web: https://community.bit9.com/groups/developer-relations
E-mail: dev-support@bit9.com

### Reporting Problems

When you contact Bit9 Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM) 
* For documentation issues, specify the version of the manual you are using. 
* Action causing the problem, error message returned, and event log output (as appropriate) 
* Problem severity
