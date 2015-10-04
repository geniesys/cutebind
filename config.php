<?php
/*
	This is cutebind configuration file. Modify these settings according to your environment
    and save as config.my.php to prevent accidental override.
*/
define('IS_64b',TRUE);
$settings['DEBUG']       = FALSE;				// Prints various debugging information mostly about what it is doing. There are many commented-out lines of code that can be used to debug particular portion of the code.
$settings['listen']      = '192.168.1.16';			// IP to listen on (IP address of this host)
$settings['listen_port'] = 53;					// DNS-server port
$settings['minDNSworkers']=10;					// Minimum/Initial number of workers
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
				'txt'       => 'www.domain.tld/sbl',	// Short text and/or URL returned along with the IP. Usually indicates the reason and/or where sender can obtain additional information.
				'min_age'   => 7			// Minimun age in days of the domain attempting connection. Default is 7 days. "0" disables this feature.
				);

$settings['mysql']	 = array(				// Parameters for your MySQL connection
				'host' => '192.168.1.17',   // IP address of your MySQL server or localhost
				'port' => '',               // default port is 3306
				'user' => 'cutebind',       // also see cuteresolve.sql (bottom of the file)
				'pass' => 'password',       // also see cuteresolve.sql (bottom of the file)
				'base' => 'cuteresolve'		// 'cuteresolve' is the default schema name for this project.
			);

/*
    $REJECT_REASON_ENUM allows for translation of numeric return codes from sbl module to textual messages.
    Corresponding value is appended to $settings['SBL']['txt']. The values can be customized here.
    If you use URL, please use a hash mark (#) as the first character to keep URL syntax valid.
    Default values are the same as corresponding numeric codes.
    Examples:
        1 => '#1'           -> www.domain.tld/sbl#1
        1 => '#Blacklisted' -> www.domain.tld/sbl#Blacklisted
        1 => ''             -> www.domain.tld/sbl

    Note: Being too descriptive can tip spammers.
*/
$REJECT_REASON_ENUM = array(
	1   => '#1',	// Blacklisted
	2   => '#2',	// Internal server error
	3   => '#3',	// Host/domain not found
	4   => '#4',	// (not used)
	5   => '#5',	// Mailformed IP
	6   => '#6',	// Minimun Domain Age
	7   => '#7',	// Domain is not registered or no whois server for such TLD
	8   => '#8',	// hostname contains host's IP address (ISP's usually assign generic names containing IP address which could indicate a possible dinamic IP)
	9   => '#9',	// Email contains URL(s) to blacklisted site(s)
);

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
