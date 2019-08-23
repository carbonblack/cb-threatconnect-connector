# Carbon Black - ThreatConnect Connector

Carbon Black provides integration with ThreatConnect by retrieving Indicators of
Compromise (IOCs) from specified communities. To support this integration, Carbon
Black provides an out-of-band bridge that communicates with the ThreatConnect API.

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-threatconnect-connector
```

Once the software is installed via YUM, copy the 
`/etc/cb/integrations/threatconnect/connector.conf.example` file to 
`/etc/cb/integrations/threatconnect/connector.conf`.
 Edit this file and place your Carbon Black API key into the 
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Next, place the credentials for your ThreatConnect API account into the `api_key` and `secret_key` variables. The 
`api_key` variable is the numeric API identifier issued by ThreatConnect, and the `secret_key` is a long alphanumeric +
symbols secret key assigned to you. Any special characters in the secret key do not have to be escaped in the
configuration file.

To receive IOCs from your organization as a source, enter your organization's source name in `default_org`.

To specify which sources to pull from, enter your sources as a comma separated list in `sources` or `*` to pull from all
sources.

Once you have the connector configured for your API access, start the ThreatConnect service:
```
service cb-threatconnect-connector start
```

Any errors will be logged into `/var/log/cb/integrations/cb-threatconnect-connector/cb-threatconnect-connector.log`.

## Troubleshooting

If you suspect a problem, please first look at the ThreatConnect connector logs found here: 
`/var/log/cb/integrations/cb-threatconnect-connector/cb-threatconnect-connector.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

## Contacting Carbon Black Developer Relations Support

Web: https://developer.carbonblack.com
E-mail: dev-support@carbonblack.com

### Reporting Problems

When you contact Carbon Black Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM) 
* For documentation issues, specify the version of the manual you are using. 
* Action causing the problem, error message returned, and event log output (as appropriate) 
* Problem severity
