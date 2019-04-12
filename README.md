# Carbon Black - ThreatConnect Connector

The ThreatConnect connector for Carbon Black Response is a simple python-daemon
communicats with ThreatConnect's API and retrieve Indicators of Compromise and 
formats them as a Threat Intel Feed for Carbon Black Response.

# Installing TC Agent (Centos/RHEL 6)

The TC agent must be installed on the same system as Cb Response.

* Create directories

	```
	mkdir -p /usr/share/cb/integrations/threatconnect
	```
	
* Download threatconnect Agent

	```
	wget -O /usr/share/cb/integrations/ https://github.com/carbonblack/cb-threatconnect-connector/releases/download/2.0.0/tc_agent
	```
	
* Download threatconnect Logo

	```
	wget -O /usr/share/cb/integrations/threatconnect/threatconnect-logo.png https://github.com/carbonblack/cb-threatconnect-connector/releases/download/2.0.0/threatconnect-logo.png
	```
	
* Create threatconnect Agent Config File


#### Sample TC Agent Config

	[general]
	#
	# CB Response configuration details.  This is used to create the feed in the CB Response UI automatically
	# feed_url should be the same file path as is used in out-file parameter for tc_agent
	#
	feed_url=file://tmp/threatconnect.json
	cb_server_url=https://192.168.1.42
	cb_server_token=
	cb_server_ssl_verify=False
	
	
	#
	# This section allows global configuration options to be passed to the ThreatConnect feed.
	# The API_KEY is an integer value and should not be enclosed in quotes.
	# Utilize the API and Secret keys provided by ThreatConnect to access your specific community.
	#
	
	#
	# Base URL for ThreatConnect
	#
	base_url=https://sandbox.threatconnect.com/api
	
	access_id=
	
	secret_key=
	
	#
	# The default organization to pull IOCs
	#
	default_org=Carbon Black
	
	#
	#
	#
	sources=Carbon Black
	
	#
	# This agent allows for the custom "CB Alert" type to be added to the Threat Connect feed.
	#
	ioc_types=CB Alert
	#
	# Maximum number of IOCs to put in feed.  CB Response has a limit to the number of threat reports in a feed for
	# for performance reasons.
	#
	max_iocs=10000

	
* copy and modify the above config to `/etc/cb/integrations/threatconnect/threatconnect_agent.conf`

#### Running threatconnect Agent Manually

	./tc_agent --config-file=/etc/cb/integrations/threatconnect/threatconnect_agent.conf --out-file /usr/share/cb/integrations/threatconnect/tc.json --log-file /var/log/cb/integrations/tc.log

#### Example Cron Entry

# Development Notes	

## threatconnect Agent Build Instructions (Centos 6)

### Install Dependencies

* zlib-devel
* openssl-devel
* sqlite-devel

### Install Python 3.6

	
	./configure --prefix=/usr/local --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib"
	make
	make altinstall


### Create VirtualEnv


	python3.6 -m venv venv-build
	source ./venv-build/bin/activate
	pip install -r requirements.txt


### Create Executable


	pyinstaller main.spec

## Configuration

The tc_agent is controlled by a simple conf file. 

There is an example threatconnect.example.conf provided in the git repository.

The `[general]` stanza of the provided .conf file should include the required
configuration paramters for accessing ThreatConnect - some of which are optional.

`base_url=<string>` controls the destination ThreatConnect endpoint

`secret_key=<string>` controls the secret key for ThreatConnect API access

`access_id=<string>` controls the acces id for ThreatConnect API access

`defaulg_org=<string>` controls the deafult org when filtering IOCS

`sources=comma,deliminted,list` controls the sources to query for, optional - 
defaults to all available

`ioc_min=<int>` controls the minimum IOC value to include, optional

`ioc_types=comma,delimited,list` controls the IOC Types to gather - defaults to 
'File,Address,Host' - optional

`custom_ioc_key` controls the custom IOC field/key to look for when using CUSTOM IOCS
Defaults to 'Query', optional


The following configuration options are for creating and presenting the 
Threat Inteligence Feed to CbR via REST API.

`cbapi_key=<string>` api key to use when access CBR api 

`cbapi_hostname=<string>` fqdn to use when accessing CBR

`cbapi_ssl_verify=<bool> True/False` used to control ssl validation for CBR API - defaults to TRUE

`feed_url` feed url to use when advertising the feed to CBR

The following are optinal misc options:
`niceness=<int>` controls os.nice of the daemon

`debug=<bool>` controls the debug logging of deamon set True/False

##Support
Contact dev-support@carbonblack.com
