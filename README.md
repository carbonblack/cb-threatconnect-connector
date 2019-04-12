# Carbon Black - ThreatConnect Connector

The ThreatConnect connector for Carbon Black Response is a simple python-daemon
communicats with ThreatConnect's API and retrieve Indicators of Compromise and 
formats them as a Threat Intel Feed for Carbon Black Response.

## Installation Quickstart

You must install the connector by retrieing the sourcecode from github. 

You can download the tarball of the repository and extract it into a location 
of your choice or checkout the code using:

`git clone https://github.com/carbonblack/cb-threatconnect-connector`

Prepare a threatconnect.conf configuration file to setup the daemon, by following
the provided example and the configuration subsection below.

You can run the threatconnnect connector by executing main.py with python or by 
building the executable for your system using the instructions below.

`./tc_agent --config-file threatconnect.conf`

The agent will begin polling threat connect periodically.

## Configuration

The connectdor is controlled by a simple conf file. 

There is an example threatconnect.example.conf provided in the git repository.

The `[general]` stanza of the provided .conf file should include the required
configuration paramters for accessing ThreatConnect - some of which are optional.
`base_url=<string>` controls the destination ThreatConnect endpoint
`secret_key=<string>` controls the secret key for ThreatConnect API access
`access_id=<string>` controls the acces id for ThreatConnect API access
`defaulg_org=<string>` controls the deafult org when filtering IOCS
`polling_interval=<val><spec>` like `polling_interval=5M` for 5 minute polling.
`outfile=<string-filepath>` controls the output file name and destination 

`sources=comma,deliminted,list` controls the sources to query for, optional - 
defaults to all available
`ioc_min=<int>` controls the minimum IOC value to include, optional
`ioc_types=comma,delimited,list` controls the IOC Types to gather - defaults to 
'File,Address,Host' - optional
`custom_ioc_key` controls the custom IOC field/key to look for when using CUSTOM IOCS
Defaults to 'Query', optional
`polling_interval=<val><spec>` like `polling_interval=5M` for 5 minute polling.
`outfile=<string-filepath>` controls the output file name and destination 
Valid specs are Minutes, Hours, Weeks, Seconds.

The following configuration options are for creating and presenting the 
Threat Inteligence Feed to CbR via REST API.

`cbapi_key=<string>` api key to use when access CBR api 
`cbapi_hostname=<string>` fqdn to use when accessing CBR
`cbapi_ssl_verify=<bool> True/False` used to control ssl validation for CBR API - defaults to TRUE
`feed_url` feed url to use when advertising the feed to CBR

The following are optinal misc options:
`niceness=<int>` controls os.nice of the daemon
`debug=<bool>` controls the debug logging of deamon set True/False
`logfile=<string-filepath>` controls the logging file name and destination

## PyInstaller and  Building the Agent as an Executable 
Use pip to install the project requirements like:
`pip install -r requirements.txt`

Use `pyinstaller main.spec`, the executable agent will be dist/tc_agent. 

Run the agent and pass --config-file to supply the path to the configuration file

##Support
Contact dev-support@carbonblack.com
