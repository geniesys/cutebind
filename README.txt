
CuteBind 2.x

Second generation Powerful scriptable DNS-server with SBL/SURBL functionality. LGPL.

All key features of original CuteBind 0.1b are preserved:
 - Full resolving control (scripting).
 - Advanced requests logging (optional).
 - Great performance (12000 requests per SECOND is easy-peasy).
 - Dynamic multi-threading (internal load balancing).
 - You can use it with MySQL or other databases.
 - Built-in Round-robin load balancing.
 - Built-in name resolution table.

New features added:
 - Can work as DNS Proxy, DNSBL/SBL service as well as host Zones (zone transfers are
   not supported).
 - Supports all major DNS records: A, AAAA (IPv6), CNAME, NS, MX, PTR, SOA, SRV, TXT,
   HINFO.
 - Performs recursive lookups to obtain actual IP addresses when needed (in case of
   CNAME records, for example).
 - Server is now caches all external lookups further improving its performance and
   mitigating risks of overloading your other servers should you experience DDoS attack.
 - A mechanism that avoids parallel external lookups for identical queries. It has been
   noted that web browsers fire a bunch of identical request (usually 4) all at the
   same time. This mechanism tries to answer these requests using cache rather than
   forwarding all of them to the parent DNS.
 - Dynamic Expiration Time Adjustment mechanism automatically adjusts cached record
   expiration time based on server load to achieve better cache utilization.
 - Code is reorganized for better manageability.

--------------------------------------------------------------------------------------
					INSTALLATION
--------------------------------------------------------------------------------------
* Note to Ubuntu users
  When program is run in CLI mode (not as deamon), there is a problem terminating
  it via Ctrl+C. This issue appears to be common problem in Ubuntu and has been around
  for quite some time. At this time, we're still looking for a solution or workaround.
  Meantime, please use one of the following methods to terminate the program:

  a) From separate terminal window execute 'sudo cutebind stop'

  b) Ctrl+Z then type 'sudo kill -2 <PID>' (PID is shown in when program starts or look
     into 'cutebing.pid' file or 'ps -ef | grep cutebind' and get the id of 'master'
     process which is smallest number).


Install PHP 5 standard package (latest stable). [Also works with PHP 7]

	Depending uppon version of your Linux, PHP may come in different packaging.
	This software (CuteBind) depends on the following libraries which in some
	distributions are included by default and considered optional in others.

	pcntl, sockets, shmop, posix, mysql


	If your installer allows arguments, then specify the following parameters
	to the installer:

	--enable-pcntl --enable-sockets --enable-shmop --enable-posix

	Otherwise, procede without additional parameters and then add necessary modules
	after initial installation.

	To install standard PHP distribution:

	Ubuntu:		sudo apt-get install php5

	openSUSE:	[sudo] zypper install php5


	Type php -m to see which libraries are included in standard installation.

	Add missing modules:

	Ubuntu 14.04.x LTS + PHP5:
		sudo apt-get install php5-mysql

	Ubuntu 16.04.x LTS + PHP7:
		sudo apt-get install php7.0-mysql
		sudo apt-get install php7.0-cli		(optional)

		* Yes, it works on PHP 7.0

	openSUSE:
		[sudo] zypper install php5-pcntl
		[sudo] zypper install php5-sockets
		[sudo] zypper install php5-shmop
		[sudo] zypper install php5-posix

		* Confirmed to work on openSUSE 13.1 and Leap 42.2 with PHP 5.2.6 - 5.5.14



Check if your Linux OS has 'whois' utility. If not, install it from online
software repository for your OS.

	Ubuntu  :	sudo apt-get install whois 
	openSUSE:	[sudo] zypper install whois

Download cutebind source

	<GitHub instructions needed> 

	Suggested destination folder is "/usr/local/cutebind".
	If you are not 'root', you may not be able to save directly into this location.
	Workaround is to save the application files in a location to which you do have
	writeable access and then 'sudo mv <source_path>/cutebind /usr/local/' .
	
	CuteBind's location is not very important, but what helps to run it as a system
	service is a couple of symbolic links in /usr/local/bin and /usr/bin

	$ cd <CuteBind's_folder>
	$ CWD=$(pwd);
	$ ln -sf $CWD/cutebind.sh /usr/local/bin/cutebind;
	$ ln -sf $CWD/cutebind.sh /usr/bin/cutebind;
	$ ln -sf $CWD $HOME/Desktop/cutebind;			# Optional link on your Desktop

	install.bash script assists you with this process including creation of symlinks
	and database initialization. Don't run it yet. We have a couple of aditional steps
	to complete before we get there.


If necessary, modify "shebang" header of cutebind's executable.
	PHP installation on Ubuntu and openSUSE repository places PHP into /usr/bin/php.
	Other brands of Linux may place PHP in different location.
	Type "which php" to verify where it is.

	If it is not '/usr/bin/php' then modify Line 1 of cutebind.sh
	and enter correct path. For example, change '#!/usr/bin/php -q' to '#!/opt/php -q'

Modify config.php according to you environment.
	Change 'listen' IP to host's IP address.
	Change 'host' IP in $settings['mysql'] section.
	Check/modify other parameters as necessary. Read comments next to each parameter.

	* If you're using AWS EC2 instance, the 'listen' IP is your 'Private IP', but
	you must refer to your DNS server using 'Public IP' or 'Public DNS' name. Both IP
	addresses are shown in the 'Description' tab (details frame) for that EC2 instance.


Now you can run ' ./install.bash' or '. ./install.bash'


--------------------------------------------------------------------------------------
					TEST
--------------------------------------------------------------------------------------



--------------------------------------------------------------------------------------


DNS Cache
----------

	DNS Cache Statistics
	--------------------
	Log analysis shows that DNS Cache feature resolves over 59% of request (on
	average) locally without having to forward request to parent DNS.
	Statistics were collected over 10 days period. Two Windows machines were
	set up as clients that used this DNS Server exclusively. One of them is mail
	server. 3/4 of traffic is generated by web browsing activity. Your results
	may vary depending on how you use it.


Cutebind as DNSBL/SBL service
-----------------------------
	* This DNS server can also serve a role of spam filtering service. Your mail
	server must support DNSBL type services.

	What is DNSBL service?
	----------------------
	DNSBL service is a DNS-based Block List service intended to reduce amount of spam
	that comes into your mail server. There is a number of paid and free DNSBL
	services on the Internet. These services maintain a large number of so called
	"honeypot" mailboxes. An automated process analyzes who sends mail to these
	mailboxes and adds sender IP addresses to BL database. Your mail server checks
	IP addresses of incoming connections against one or more DNSBL services. If any
	one of these services reply that this IP is listed then connection is rejected.
	Spammers (and businesses that facilitate such activity) are quite aware of these
	measures. They use various techniques to avoid detection and exploit weaknesses
	of DNSBL services. Such techniques include domains that exists only for a day,
	frequent IP address rotation, and use of unregistered (anonymous) IP addresses.

	From author's personal oservation, free DNSBL services seem to block less than a
	half of spam. Despite this fact, you should not disregard them. It has been noted
	that vast majority of unsolicited mail that doesn't get blocked by DNSBL's comes
	from unregistered (anonymous) IP addresses. These addresses do not have a host
	associated with it. Not even a generic name assigned by an ISP.
	The RFC standard does not require sender to maintain a domain or PTR record for
	the host in order to send mail. Since this is not a requirement, many mail servers
	and DNSBL services do not check for this fact. It would be against RFC standard.
	Requirement or not, author of this feature has found this to be an problem.
	I have never seen a legitimate email that came from anonymous IP. Have you?


	DNSBL/SBL Statistics
	--------------------
	Log analysis shows that DNSBL "Anonymous IP" blocking rule blocks 71.8% connection
	attempts on average. Statistics were collected over 10 days period for a small,
	private domain. Your results may vary.


	Extending SBL feature
	---------------------
	As of version 2.0, cutebind includes provisions to serve as your own DNSBL/SBL
	service. Three built-in functions are provided to achive this goal:
	1) dnsbl_whitelist()	- implements database-based "whitelist" functionality;
	2) dnsbl_blacklist()	- implements database-based "blacklist" functionality;
	3) dnsbl_anonymous_ip()	- implements detection of "Anonymous IP's"

	Version 2.1
	4) sbl_domain_age() 	- implements detection and blocking based on domain age.

	Version 2.2
	5) surbl_check($domain) - implements SURBL functionality.

	Two additional functions sbl_hostname_contains_ip() and sbl_test_ports() are
	also included, but currently do not participate in the DNSBL desicion process.

	You may extend SBL feature even	further by adding more rules. Below are some ideas
	of the logic that user-defined rules can do:

	- maintain a list of known spammers (database);
	- blocking based on geographical location;
	- statistical analysis (how many emails came from this IP in a period of time);
	- "v=spf1..." text record analysis;

	* Verifications such as presence of an MX record and "v=spf1..." text record
	analysis cannot be reliably done at this point. You will need to consider
	value of "From:" header as well.

	Keep in mind that this is not a spam filtering software. At this point, email
	message hasn't actually arrived yet into you mail server, so there is not much
	you can do in terms of SMTP headers and content analysis. Here, we have only
	sender's IP address to work with. Doing PTR lookup opens up a few more
	possibilities, but that's about it. This SBL feature is first line of defense.
	Its purpose is to reject certain senders before their mail clogs your mail
	server or spam filtering software.


	Configuration
	-------------
	In order to differentiate between normal DNS lookups and SBL lookups you must
	refer to this DNS server using different hostname. In you primary DNS you should
	create separate host record such as 'sbl.example.com' and specify the same IP
	address as the other one.

	Example:
	ns1.example.com -> (A) '192.168.1.5'		# Primary DNS
	ns2.example.com -> (A) '192.168.1.6'		# this DNS
	sbl.example.com -> (A) '192.168.1.6'		# this DNS

	In your mail server or spam filtering software you must refer to this server by
	its "sbl" name.

	SBL Configuration example for multiple services including your own:

						IP Address returned
	Service Name         DNS Lookup Domain	when host is listed	Response text if denied
	-------------------- -----------------	-------------------	-------------------------------------------------
	Spamhaus SBL (Spam)  sbl.spamhaus.org	127.0.0.2       	Spamhaus SBL (Spam) - http://www.spamhaus.org/sbl
	CBL (Spam)           cbl.abuse.org   	127.0.0.2       	CBL (Spam) - http://cbl.abuseat.org/
	Spamcop (Spam)       bl.spamcop.net  	127.0.0.2       	Spamcop (Spam) - http://spamcop.net/bl.shtml
	Example.com (Spam)   sbl.example.com 	127.0.0.2       	REJECTED/SPAM - http://www.example.com/sbl


	SBL lookup requests originated from your mail server or spam filtering software
	will look like '182.127.253.188.sbl.example.com.' (query type is 'A') where
	numeric prefix is the IP address to be looked up (in revese order) and the rest
	is the DNS Lookup Domain configured for this service.

	config.php
	----------
	Config.php contains four settings related to SBL processing:

	'hostmatch'
	  This string must fully or partially match the "sbl" name given to your DNS
	  server. When server sees this string in the name being resolved the SBL process
	  is triggered. Otherwise, regular resolution is performed.
	  Comparison is case sensitive. Always keep it in lowercase.Make sure the value
	  of 'hostmatch' is not too ambiguous. For example, checking only for 'sbl.'
	  would interfere with 'sbl.spamhaus.org'. '.sbl.example.' is good enough.
	  Checking for '.sbl.example.com.' guarantees exact match, but in a configuration
	  that uses Conditional Forwarder (your primary DNS forwards certain queries to
	  this server) you will not be able to setup such forwarder if that server
	  already hosts your domain (i.e. you can't have forward lookup zone for
	  example.com and have Conditional Forwarder for example.com at the same time).
	  If you run into situation like this, try sbl.example.local or make up some
	  dummy domain. You primary DNS must be able to resolve this name into an IP
	  address. Use any means available including static entries in hosts/lmhosts files.

	'return_ip'
	  This is the IP address to be returned when sender is rejected. Usually, it is
	  in 127.0.0.[2-9] range with .2 being most common. Other numbers indicate
	  various reasons for rejections. Check your mail server documentation
	  for expected IP address.

	'txt'
	  Text and/or URL returned along with the IP. Usually indicates the reason
	  and/or where sender can obtain additional information.

	'min_age' (number of days, numeric)
	  Minimun age in days of the domain attempting connection. Default is 7 days.
	  Enter "0" to disable this feature. You can also add trusted domains such as
	  those under your control to the whitelist.


	sbl_lookup.php
	--------------
	This file contains code related to DNSBL processing.
	Additional user-defined functions can be added to this file. Any PHP programmer
	should be able to understand what needs to be done by analyzing the code in this
	file. If you come-up with a useful rule please concider sharing it with others.

	
Changing Default DNS Timeout Settings
-------------------------------------
	CuteBind uses PHP function get_dns_records() to perform external lookups. This
	function relies on network settings of your system, including DNS related
	parameters. In certain Linux builds default DNS request timeout may be set too
	long. For example, in openSUSE 13 default timeout is around 25-30 sec. You may
	not even notice that because clients such as web browser terminate request much
	sooner - after about 5 sec. Behavior of the get_dns_records() function is
	different. This function waits for response until system terminates connection.

	If you notice that some workers "hang" for unjustifiably long time, you may want
	to decrease this timeout.

	openSUSE 13:
		run YaST2
		navigate to System -> /etc/sysconfig Editor
		navigate to Network -> General -> NETCONFIG_DNS_RESOLVER_OPTIONS
		add "timeout:5"
		You may also add key "attempts:1" if you prefer
		Click "Ok"
		$ cat /etc/resolv.conf		to verify that changes were saved


	Other Linux builds:
		Please do your research for your Linux.
		Ask google for "options timeout:" and "NETCONFIG_DNS_RESOLVER_OPTIONS"


Resolving Issues and Debugging
------------------------------
	Cutebind includes built-in error logging and debugging features.

	Processing errors and issues are recorded in ./logs/error.log. You should
	periodically review this file. Content can be deleted after review.

	Should it become necessary to troubleshoot an issue you can put cutebind into debug
	mode. It can be done in two ways:
	a) Change value of $settings['DEBUG'] to TRUE and restart cutebind.
	b) Send signal SIGHUP to master process (kill -HUP <process_id>).

	To turn debugger off change $settings['DEBUG'] back to FALSE or send another SIGHUP.

	If you are running Cutebind as a service, you need to stop this service and start
	the program in console.
		$ cd /<path to cutebind>
		$ cutebind master

	It is recommended to temporary limit number of clients that use this DNS server
	while it is in debug mode.


Customizing Cutebind
---------------------
	If you are planning to customize this program you may want to start with function
	resolver() located in config.php. This function is provided exactly for this
	purpose. resolver() is called after after built-in resolution table and internal
	cache have been checked, but before external lookup is performed. In most custom
	implementations, resolver() would query a database resource.
	Keep in mind that whatever you task this function to do must complete relatively
	fast. Answer must be obtained within a second or less.
