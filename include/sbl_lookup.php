<?php

function sbl_lookup( &$q, &$a ) {	// Spam Block List (SBL) handler
/*
	This is the place where you can customize you SBL processing.
	Customization would usually include calls to other functions. This function is intended to
	direct the process and analyze return codes. Your function(s) should take $q and $a as input
	parameters, update $a in the process, and return a numeric return code.
	This code is returned back to parent process where it updates $qinfo['REPLYCODE'].

	Keep in mind that this is not a spam filtering software. At this point, email message hasn't
	actually arrived yet into you mail server, so there is not much we can do in terms of SMTP
	headers and content analysis. Here, we have only sender's IP address to work with. Doing
	PTR lookup opens up a few more posibilities, but that's about it.
	This SBL feature is first line of defence. Its purpose is to reject certain senders before
	their mail clogs your mail server / spam filtering software.

	The following detection methods are built into the system:
	Release 2.0
	- Database-based "whitelist" and "blacklist";
	- "Anonymous IP" address detection (IP has no associated host);
	- Host name contains host's IP address. ISP's often use generic names that repeat host IP
	  address in some form. This rule is intended to detect such pattern (this rule is inactive);
	- Port test. Check whether any standard SMTP and IMAP ports are open on sender's side.
	  (This rule is inactive. It also delays server response by a second or so.)

	Release 2.1
	- Domain Age Verification. This rule extracts domain creation date from public domain
	  registration records and returns domain age in days. This rule is intended to block
	  incoming connections from recently created domains. Default value is 7 days. You can
	  disable this feature by setting $settings['SBL']['min_age'] in config.php to "0".
	  You can also add trusted domains such as those under your control to the whitelist.
	  * Note: Failed lookups will not cause "blocked" status.

	Release 2.2
	- The SBL lookup process is split into two branches - DNSBL and SURBL functionality.
	  DNSBL makes desicions based on IP addresses.
	  SURBL makes desicions based on domain/host names extracted from links in message body.

	Below are some ideas on the logic that your custom rules can do:
	- statistical analysis (how many emails came from this IP in a period of time);
	- blocking based on Geographical location;
	- "v=spf1..." text record analysis (to do it properly you'll also need value of "From:"
	  header which we don't have at this point);
*/
	global $settings, $REJECT_REASON_ENUM;
	$rejection_reason = 0;
	$matches;

	// Check whether $q->host starts with an IP address pattern such as 4.3.2.1.sbl.domain.tld.
	if( preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(.+)$/', $q->host, $matches) ) {
		// Yes, $q->host contains an IP address. Do DNSBL processing.

		//$e = explode('.',$q->host);
		//$q->IP = $e[3].'.'.$e[2].'.'.$e[1].'.'.$e[0];		// 4.3.2.1.sbl.domain.tld. -> 1.2.3.4
		$q->IP = $matches[4].'.'.$matches[3].'.'.$matches[2].'.'.$matches[1];		// 4.3.2.1.sbl.domain.tld. -> 1.2.3.4

		if( dnsbl_whitelist($q->IP) ) {
			$replycode = 0;			// Allow - IP is whitelisted. No further checks needed.
		} elseif( dnsbl_blacklist($q->IP) ) {
			$replycode = 3;			// Block - IP is blacklisted. No further checks needed.
			$rejection_reason = 1;
		} else {
			$replycode = dnsbl_anonymous_ip($q,$a,$q2,$a2);
			/*
			dnsbl_anonymous_ip() return codes:
				0 = Successful
				2 = Internal server error
				3 = Host/domain not found
				5 = Mailformed IP
			*/
			$rejection_reason = $replycode;

			if($replycode == 0) {

				$age = sbl_domain_age($q2, $a2);

				/*
				sbl_domain_age() executes 'whois' for a domain in question, extracts domain creation date from the result.
				Returns:
					false	- unable to parse domain registration date or no such value found in the whois output;
					0 (int)	- domain is not registered or there is no whois server for such TLD;
					>1(int)	- difference in days between domain creation date and current date;
				*/

				//echo '$age = '.$age."\n";

				if( $age === false ) {
					if($settings['DEBUG']) echo "[DEBUG] sbl_lookup() - Unable to parse domain registration date or no such value found in the whois output\n";
				} elseif( $age === 0 ) {
					if($settings['DEBUG']) echo "[DEBUG] sbl_lookup() - Domain is not registered or there is no whois server for such TLD\n";
					$replycode = 3;
					$rejection_reason = 7;
					dnsbl_blacklist_add($q->IP,'Domain is not registered or no whois server for such TLD');
				} elseif( $age < $settings['SBL']['min_age'] ) {
					if($settings['DEBUG']) echo "[DEBUG] sbl_lookup() - Insufficient domain age: $age < $settings[SBL][min_age]\n";
					$replycode = 3;
					$rejection_reason = 6;
					dnsbl_blacklist_add($q->IP,'Insufficient domain age');
				}

			} elseif($replycode == 3) {
				dnsbl_blacklist_add($q->IP,'Anonymous IP');
			}
		}

		// Do additional steps based on $replycode value obtained above.

		if ( $replycode == 0 ) {		// 0 = This IP has associated host or whitelisted.

			/*  What to return in "not-blocked" situation depends on your spam filter / mail server.
			    Usually, SBL verification only acts upon 127.0.0.x responses and ignores everything else.
			    This is something you'll need to find out in the documentation and/or run some tests.*/

			if( isset($q2) ) {			// Did we run dnsbl_anonymous_ip()? If we didn't $q2 and $a2 will not be set and cannot be used.

				// Option 0 - Comment out next 2 options if client expects nothing (0 ANSWERs) in return.

				// Option 1 - Return IP address of the host (which is basically the same address that was asked in question) followed by PTR record.
				// Both records are part of ANswer collection.
				$a->set_type('A');
				$a->AN['A'] = Array($q2->IP => Array ('ttl' => $settings['DNS']['TTL']));
				$a->AN['PTR'] = $a2->AN['PTR'];

				// Option 2 - If above doesn't work try sending PTR as ADditional record.
				// Use with caution! My email server doesn't care if PTR follows, but MS DNS Server rejects entire answer.
				//$a->set_type('A');
				//$a->AN['A'] = Array($q2->IP => Array ('ttl' => $settings['DNS']['TTL']));
				//$a->AD['PTR'] = $a2->AN['PTR'];

				// Option 3 - Respond with dummy IP address (must not be 127.0.0.x).
				//$a->set_type('A');
				//$a->AN['A'] = Array('0.0.0.0' => Array ('ttl' => $settings['DNS']['TTL']));		// add dummy record to ANswer collection

				// Option 4 - Respond with different type of record.
				/* It is also possible to return only PTR obtained in 2nd lookup which has the host name, but
				   this may not be legal from DNS standard point of view because question was for 'A'.
				   Anyways, if this is what you spam filter wants, use next two lines instead of the above. */
				// $q->IP = $q2->IP;
				// $a = $a2;

				if( dnsbl_hostname_contains_ip($q2,$a2) ) {
					$a->src = '$';		// To be verified
					$rejection_reason = 8;
				} else {
					$a->src = '@';		// Allowed
				}

			} else {			// No, we did not run dnsbl_anonymous_ip(). This IP is whitelisted.

				$a->set_type('A');
				$a->AN['A']   = Array('1.1.1.1'   => Array ('ttl' => $settings['DNS']['TTL']));		// add A record to ANswer collection
				$a->AN['PTR'] = Array('whitelist' => Array ('ttl' => $settings['DNS']['TTL']));		// add PTR record to ANswer collection
				$a->src = '@';		// Allowed
			}

		} elseif ( $replycode == 3 ) {		// 3 = Blacklisted or there is no host/domain associated with this IP address - BLOCK IT
			$txt = $settings['SBL']['txt'] . $REJECT_REASON_ENUM[$rejection_reason];
			$a->set_type('A');
			$a->AN['A']   = Array($settings['SBL']['return_ip'] => Array ('ttl' => $settings['DNS']['TTL']));	// add A [127.0.0.x] record to ANswer collection
			$a->AD['TXT'] = Array(                            0 => Array ('txt' => $txt));				// add TXT record to ADditional collection
			$a->src       = '#';		// Blocked
			$replycode    = 0;		// change REPLYCODE to no-error
		}

	} else {
		// No, $q->host does not contain an IP address. Do SURBL processing.
		//echo '$settings[SBL][hostmatch] = '.$settings['SBL']['hostmatch']."\n";
		$domain = substr($q->l_host,0,strpos($q->l_host,$settings['SBL']['hostmatch']));	// otherdomain.tld.sbl.mydomain.tld. -> otherdomain.tld
		switch( surbl_check($domain) ) {
		case  0 :	// neutural (not data)
			$replycode = 3;
			break;
		case  1 :	// blacklisted
			$txt = $settings['SBL']['txt'] . $REJECT_REASON_ENUM[9];
			$a->set_type('A');
			$a->AN['A']   = Array($settings['SBL']['return_ip'] => Array ('ttl' => $settings['DNS']['TTL']));	// add A [127.0.0.x] record to ANswer collection
			$a->AD['TXT'] = Array(                            0 => Array ('txt' => $txt));				// add TXT record to ADditional collection
			$a->src       = '#';		// Blocked
			$replycode    = 0;		// change REPLYCODE to no-error
		 	break;
		case -1 :	// whitelisted
			$a->set_type('A');
			$a->AN['A']   = Array('1.1.1.2'   => Array ('ttl' => $settings['DNS']['TTL']));		// add A record to ANswer collection
			$a->AN['PTR'] = Array('whitelist' => Array ('ttl' => $settings['DNS']['TTL']));		// add PTR record to ANswer collection
			$a->src       = '@';		// Allowed
			$replycode    = 0;		// set REPLYCODE to no-error
			break;
		}
		//$domain = implode('.',array_reverse(explode('.',$domain)));				// tld.otherdomain -> otherdomain.tld
		//if( $replycode = surbl_check($domain) ) {
			//switch($replycode) {}
		//} elseif( surbl_whitelist($domain) ) {
		//	$replycode = 0;			// Allow - domain is whitelisted. No further checks needed.
		//} elseif( surbl_blacklist($domain) ) {
		//	$replycode = 3;			// Block - domain is blacklisted. No further checks needed.
		//	$rejection_reason = 1;
		//}
		//$replycode = 0;
	}

	//dnsbl_test_ports($q);

	return $replycode;
}

/* ----- DNSBL Functions ----- */

function dnsbl_whitelist( $ip ) {
	/*
	  This rule checks if given IP is listed in dnsbl_whitelist table.
	  Parameter $ip is expected to be a complete IP address. The value of `ip` field it is checked against
	  can be a single IP address, Class C or B subnet wildcard (i.e. 123.456.789.*, 123.456.*) or address
	  range in CIDR notation up to class B (i.e. from a.b.0.0/16 to a.b.c.d/32).
	  Wildcards like 123.456.*.* are not supported.
	  To extend CIDR range to Class A (a.0.0.0/8) code can be rewtitten as:
	  	$cidr = '^'.$arr[0].'\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}';
		SELECT ... OR `ip` REGEXP '$cidr';
	*/
	global $settings, $db;

	if( $db = connect_db() ) {

		$arr     = explode('.',$ip);
		$class_c = $arr[0].'.'.$arr[1].'.'.$arr[2].'.*';
		$class_b = $arr[0].'.'.$arr[1].'.*';
		$cidr    = $arr[0].'.'.$arr[1].'.%/__';

		$sql = "SELECT `ip` FROM dnsbl_whitelist WHERE `ip` IN ('$ip','$class_c','$class_b') OR `ip` LIKE '$cidr'";
		if ($result = $db->query($sql)) {
			//printf("$sql returned %d rows.\n", $result->num_rows);
			if($result->num_rows == 0) {		// nothing found - exit now returning FALSE.
				$result->close();
				return false;
			}

			while ($row = $result->fetch_array(MYSQLI_NUM) ) {
				if( $row[0] == $ip || $row[0] == $class_c || $row[0] == $class_b) {
					$result->close();
					return true;		// $ip matches `ip` or wildcards - exit now returning TRUE.
				} elseif( substr($row[0], -3, 1) == '/' ) {
					if( ipCIDRCheck($ip, $row[0]) ) {
						$result->close();
						return true;	// $ip matches CIDR - exit now returning TRUE.
					}
				}
			}
		}
	}
	return false;
}

function dnsbl_blacklist( $ip ) {
	/*
	  This rule checks if given IP is listed in dnsbl_blacklist table.
	  Parameter $ip is expected to be a complete IP address. The value of `ip` field it is checked against
	  can be a single IP address, Class C or B subnet wildcard (i.e. a.b.c.*, a.b.*) or address
	  range in CIDR notation up to class B (i.e. from a.b.0.0/16 to a.b.c.d/32).
	  Wildcards like a.b.*.* are not supported.
	  To extend CIDR range to Class A (a.0.0.0/8) code can be rewtitten as:
	  	$cidr = '^'.$arr[0].'\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}';
		SELECT ... OR `ip` REGEXP '$cidr';
	*/
	global $settings, $db;

	if( $db = connect_db() ) {

		$arr     = explode('.',$ip);
		$class_c = $arr[0].'.'.$arr[1].'.'.$arr[2].'.*';
		$class_b = $arr[0].'.'.$arr[1].'.*';
		$cidr    = $arr[0].'.'.$arr[1].'.%/__';
		$retval  = false;

		$sql = "SELECT `ip` FROM dnsbl_blacklist WHERE `ip` IN ('$ip','$class_c','$class_b') OR `ip` LIKE '$cidr'";
		if($result = $db->query($sql)) {
			//printf("$sql returned %d rows.\n", $result->num_rows);
			if($result->num_rows == 0) {		// nothing found - exit now returning FALSE.
				$result->close();
				return false;
			}

			while ($row = $result->fetch_array(MYSQLI_NUM) ) {
				if( $row[0] == $ip || $row[0] == $class_c || $row[0] == $class_b) {
					$result->close();
					return true;		// $ip matches `ip` or wildcards - exit now returning TRUE.
				} elseif( substr($row[0], -3, 1) == '/' ) {
					if( ipCIDRCheck($ip, $row[0]) ) {
						$result->close();
						return true;	// $ip matches CIDR - exit now returning TRUE.
					}
				}
			}
		}
	}
	return false;
}

function dnsbl_blacklist_add( $ip, $reason='' ) {
	/*
	  Add IP address to blacklist.
	*/
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "REPLACE INTO dnsbl_blacklist(ip,date_added,date_expires,source) VALUES ('$ip',CURRENT_TIMESTAMP,DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 30 DAY),'sbl_lookup.php: ".$reason."')";
		return $db->query($sql);
	}
	return false;
}

function dnsbl_anonymous_ip( &$q, &$a, &$q2, &$a2 ) {
	/*
	  This rule checks if given IP address has a hostname associated with it. If not, returns 'A' with IP 127.0.0.2 followed by a TXT record.
	*/
	global $settings;

	$q2 = new Question;			// partial initialization - just set a few properties that rev_lookup() actually uses
	$e = explode('.',$q->host);
	$q2->host = $e[0].'.'.$e[1].'.'.$e[2].'.'.$e[3].'.in-addr.arpa.';	// 4.3.2.1.sbl.domain.tld. -> 4.3.2.1.in-addr.arpa.
	$q2->IP   = $e[3].'.'.$e[2].'.'.$e[1].'.'.$e[0];			// 1.2.3.4
	$q2->set_type('PTR');
	$q2->set_class('IN');

	$a2 = new Answer($q2);

	if($settings['DEBUG']) echo "[DEBUG] sbl_lookup() - Checking if '".$q2->IP."' has a hostname\n";

	$replycode = rev_lookup($q2,$a2);

	if($settings['DEBUG']) echo '$a2 = ' && print_r($a2);

	return $replycode;
}

function dnsbl_hostname_contains_ip(&$q2,&$a2) {
/*
	Analyzes hostname returned by rev_lookup() for presence of an IP address.
	We are attempting to detect whether hostname returned by previous PTR lookup contains parts of the host's IP address.
	ISP's often use generic names that repeat host's IP address in some form. Example: 86-45-98-221-dynamic.agg2.kle.prp-wtd.eircom.net.
	This rule attempts to detect such pattern. Returns TRUE if all four parts of an IP address are found.
*/
	$found = true;
	$arr = explode('.',$q2->IP);
	foreach($arr as $v) {
		if( strpos(key($a2->AN['PTR']),$v) === false ) { $found = false; break;}
	}
	return $found;
}

function dnsbl_test_ports(&$q) {
/*
	Check whether standard SMTP or IMAP ports are open on sender's side.
	This rule alone should not be used to disqualify the sender. SMTP standard allows sending mail from any IP address regardless whether it
	can or cannot accept mail in return. Status returned by this function should be treated as supplemental information that adds or
	substarcts "weight" to your final desicion.

	(!) THIS FUNCTION DELAYS SERVER RESPONSE BY 1.25 sec. DO NOT USE IF ANY OF CLIENTS TIMEOUT IN LESS THAN 2 sec.
*/
	$retval = false;	// assume FALSE (all ports are closed)

	foreach(array(25,143,465,993,2525) as $port) {
		echo str_pad($q->IP.':'.$port,30,'.');
		// either method offers identical performance
		//$fp = @stream_socket_client("tcp://".$q->IP.':'.$port, $errno, $errstr, 0.25);
		$fp = @fsockopen($q->IP, $port, $err, $err_string, 0.25);

		if($fp) {
			echo "OPEN\n";
			$retval = true;
			fclose($fp);
		} else {
			echo "CLOSED\n";
		}
	}

	return $retval;
}

/* ----- Domain verification Functions ----- */

function sbl_domain_age( &$q2, &$a2 ) {
/*
	Executes 'whois' for a domain in question, extracts domain creation date from the result.
	Returns:
		false	- unable to parse domain registration date or no such value found in the whois output;
		0 (int)	- domain is not registered or there is no whois server for such TLD;
		>1(int)	- difference in days between domain creation date and current date;
*/
	global $settings, $dns_cache, $db;

	// do nothing if configuration parameter 'min_age' < 1 or is not set
	if(!isset($settings['SBL']['min_age']) || $settings['SBL']['min_age'] < 1) return false;

	$e = array_reverse(explode('.',key($a2->AN['PTR'])));
	$str_domain = $e[1].'.'.$e[0];

	// Check DNS cache for parameter 'age' added by previous lookup.
	// If not in cache, check database. If found, put it back into cache and return the value.
	if( isset( $dns_cache['table'][$str_domain]['age'] )) {
		return $dns_cache['table'][$str_domain]['age'];
	} elseif( $age = sbl_domain_age_get( $str_domain ) ) {
		$dns_cache['table'][$str_domain][0]    = time()+(60*60*12);	// expires in 12 hours
		$dns_cache['table'][$str_domain]['age']= $age;
		return $age;
	}

	// Otherwise continue with whois lookup

	//echo '$ whois '.$str_domain."\n";
	exec('whois '.$str_domain, $output);

	foreach($output as $line) {
		switch(true) {
		case( stripos($line,'creat') !== false && stripos($line,'date') !== false && strpos($line,':') !== false):
			$d = $line;
			break;
		case (stripos($line,'created on:')    !== false):
			$d = $line;
			break;
		case (stripos($line,'[created on]')   !== false):
			$d = $line;
			break;
		case (stripos($line,'registration date:') !== false):
			$d = $line;
			break;
		case (stripos($line,'created:')       !== false):
			$d = $line;
			break;
		case (stripos($line,'registered on:') !== false):
			$d = $line;
			break;
		case (stripos($line,'registered:')    !== false):
			$d = $line;
			break;
		case (stripos($line,'activated on:')  !== false):
			$d = $line;
			break;
		case (stripos($line,'Record Created') !== false):
			$d = $line;
			break;
		case (stripos($line,'no whois server')!== false):
			return 0;
			break;
		case (stripos($line,'No match for')   !== false):
			return 0;
			break;
		}

		if(isset($d)) {
			$line = trim($line);
			$d    = trim(substr($line,strpos($line,':')+1));
			break;
		}
	}

	if(!isset($d)) {
		echo "sbl_domain_age() - Unable to find line that indicates domain registration date. Below is result of whois lookup.\n";
		print_r($output);
		return false;
	}

	//echo $line."\n";

	if(date_parse($d)['error_count'] > 0) {

		// Extract date from line found above. Add patterns and corresponding replacements as needed.
		// Result of this preg should be a date string convertable by PHP date_parse() into a datetime type.

		$patterns = array(
			'/.*(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).*/'	=> '$1-$2-$3 $4:$5:$6',
			'/.*(\d{4}[-\.]\d{2}[-\.]\d{2}\s\d{2}:\d{2}:\d{2}).*/'	=> '$1',
			'/.*(\d{4})\/(\d{2})\/(\d{2}).*/'			=> '$1-$2-$3',
			'/.*(\w{3})\s(\d{1,2})\s(\d{2}:\d{2}:\d{2})\s(\d{4})/'	=> '$1 $2 $4 $3',
			'/.*(\d{2})[-\.](\w{3})[-\.](\d{4}).*/'                 => '$3-$2-$1',
			'/before Aug-1996/'                                     => '1996-07-01',	// occurs with .co.uk domains
			'/before 2001/'						=> '2000-01-01',
		);

		foreach($patterns as $p => $r) {
			//echo '$p = '.$p.', $r = '.$r."\n";
			$x = preg_filter($p, $r, $d);
			//echo '$x = '.$x."\n";
			if(date_parse($x)['error_count'] == 0) {
				$d = $x;
				break;
			}
		}
	}

	if(date_parse($d)['error_count'] == 0) {
		$date1 = new DateTime('now');
		$date2 = new DateTime($d);
		$interval = $date1->diff($date2);
		// To prevent running whois multiple times for the same domain we are going to store this interval value in $dns_cache under name 'age'.
		$dns_cache['table'][$str_domain][0]    = time()+(60*60*12);	// expires in 12 hours
		$dns_cache['table'][$str_domain]['age']= $interval->days;
		// It is also possible to store this value together with the host from which domain was extracted, but this has two potentially unwanted
		// consiquences: a) it will be removed when host expires from cache and b) it will serve its purpose only for the same remote host, not entire domain.
		// $dns_cache['table'][$q2->IP]['PTR'][key($a2->AN['PTR'])]['age'] = $interval->days;

		// If database is available, save this domain and its registeration date. This is to avoid further whois inquaries about this domain.
		if( $db = connect_db() ) {
			$sql = "REPLACE INTO domains(domain,date_registered) VALUES ('$str_domain','".date_format($date2,'Y-m-d H:i:s')."')";
			return mysqli_query($db,$sql,MYSQLI_ASYNC);
		}

		return $interval->days;
	} else {
		log_error("sbl_domain_age() - can't convert '$line' to a date. You may want to add aditional pattern to reformat this value into a date string.");
		return false;
	}
}

function sbl_domain_age_get( $str_domain ) {
	/*
	  This function retrieves domain registration date from the database and returns it as age in days (int).
	  Information in this table is obtained from previous whois lookups.
	*/
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "SELECT date_registered FROM domains WHERE domain='$str_domain'";
		if($result = $db->query($sql)) {
		    //printf("$sql returned %d rows.\n", $result->num_rows);
		    if($result->num_rows > 0) {
			$row = $result->fetch_array(MYSQLI_NUM);
			//var_dump($row);
			$date1 = new DateTime('now');
			$date2 = new DateTime($row[0]);
			$interval = $date1->diff($date2);
			$result->close();
			//echo '$interval->days = ' . $interval->days . "\n";
			return $interval->days;
		    }
		}
	}
	return false;
}


/* ----- SURBL Functions ----- */

function surbl_check($domain) {
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "CALL `surbl_check`('$domain');";
		//echo $sql."\n";
		if($result = $db->query($sql)) {
		    //printf("$sql returned %d rows.\n", mysqli_num_rows($result));
		    if($result->num_rows > 0) {
		    	$row = $result->fetch_row();
			$result->close();
			//print_r($row);
			return $row[0];
		    }
		}
	}
	return false;
}

function surbl_whitelist( $domain ) {
	/*
	  This rule checks surbl_whitelist to see if given $domain is whitelisted.
	*/
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "SELECT * FROM surbl_whitelist WHERE `domain`='$domain';";
		//echo $sql."\n";
		if($result = $db->query($sql)) {
		    //printf("$sql returned %d rows.\n", mysqli_num_rows($result));
		    if($result->num_rows > 0) {
			$result->close();
			return true;
		    }
		}
	}
	return false;
}

function surbl_blacklist( $domain ) {
	/*
	  This rule checks surbl_blacklist table to see if given $domain is blacklisted.
	*/
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "SELECT * FROM surbl_blacklist WHERE `domain`='$domain';";
		//echo $sql."\n";
		if($result = $db->query($sql)) {
		    //printf("$sql returned %d rows.\n", mysqli_num_rows($result));
		    if($result->num_rows > 0) {
			$result->close();
			return true;
		    }
		}
	}
	return false;
}

?>
