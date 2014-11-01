<?php
/*
	This is cutebind configuration file. Modify these settings according to your environment.
*/
define('IS_64b',TRUE);
$settings['listen']      = '192.168.1.16';			// IP to listen on (IP address of this host)
$settings['listen_port'] = 53;					// DNS-server port
$settings['minDNSworkers']=15;					// Minimum/Initial number of workers
$settings['maxDNSworkers']=25;					// Maximum number of workers
$settings['setuser']     = '';					// You can set user of master process (sudo).
$settings['setgroup']    = '';					// You can set group of master process (sudo).
$settings['logging']     = array(
				'date_format' => 'Y-m-d H:i:s',	// 'r' for RFC2822 formatted date (Tue, 29 Jul 2014 09:00:09 +0000). See PHP function date() to make your own format.
				'level' => 1			// Logging level (currently is not used)
				);

$settings['DNS']	 = array(
				'TTL'=> 60,			// Default Time-To-Life (TTL). If DNS record has its own 'ttl', that ttl will be used (regardless of the record source). Otherwise this value.
				'TC' => 0,			// Truncate to 512 bytes
				'RA' => 1,			// Recursive queries enabled? (1/0)
				'RR' => 15			// Use roundrobin for: 1=Inline hash-table, 2=Cached records, 4=Resolver/DB, 8=Lookups, 15=All of the above, 0=none/disabled
				);

$settings['SBL']	 = array(					// SBL queries come in form similar to '182.127.253.188.sbl.domain.tld.' where 'sbl.domain.tld' is the name given to this DNS server
				'hostmatch' => '.sbl.example.',		// and configured in your spam filter / mail server. This parameter must be equal or at least partially match this name. See README.txt
				'return_ip' => '127.0.0.2',		// IP address returned when sender is blocked. Consult your mail server documentation for the expected address. They are usually in 127.0.0.x range.
				'txt'       => 'www.domain.tld/sbl'	// Short text and/or URL returned along with the IP. Usually indicates the reason and/or where sender can obtain additional information.
				);

$settings['mysql']	 = array(				// Parameters for your MySQL connection
				'host' => '192.168.1.17',
				'port' => '',
				'user' => 'cutebind',
				'pass' => 'password',
				'base' => 'cuteresolve'		// 'cuteresolve' is the default schema name for this project.
			);

$settings['DEBUG'] = FALSE;					// Prints various debugging information mostly about what it is doing. There are many commented-out lines of code that can be used to debug particular portion of the code.


function resolver(&$q,&$a,$init = FALSE) {
/*
	This is you custom resolver() function. You can modify it to fit your needs.
	To verify that it works run "nslookup resolver.example.tld.". Answer should be "12.34.56.78".
*/
	global $settings, $db;
//	$db = connect_db();	// $db is global resource. You should be already connected.
	if ($init) return;
	if ($q->QTYPE != 'A') return FALSE;
	if ($q->host == 'resolver.example.tld.') {
		$a->set_type('A');
		$a->RDATA['A'] = Array('12.34.56.78' => Array ('ttl' => $settings['TTL']));	// add virtual record
		return TRUE;
	}
	return FALSE;
}

?>