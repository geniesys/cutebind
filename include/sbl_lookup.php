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
	- Domain age verification. This rule extracts domain creation date from public domain
	  registration records and returns domain age in days. This rule is intended to block
	  incomming connections from recently created domains. Default value is 7 days. You can
	  disable this feature by setting $settings['SBL']['min_age'] in config.php to "0".
	  * Note: Failed lookups will not cause "blocked" status.

	Below are some ideas on the logic that your custom rules can do:
	- statistical analysis (how many emails came from this IP in a period of time);
	- blocking based on Geographical location;
	- "v=spf1..." text record analysis;

*/
	global $settings;

	$e = explode('.',$q->host);
	$q->IP = $e[3].'.'.$e[2].'.'.$e[1].'.'.$e[0];		// 4.3.2.1.sbl.domain.tld. -> 1.2.3.4

	if( sbl_whitelist($q->IP) ) {
		$replycode = 0;			// Allow - IP is whitelisted. No further checks needed.
	} elseif( sbl_blacklist($q->IP) ) {
		$replycode = 3;			// Block - IP is blacklisted. No further checks needed.
	} else {
		$replycode = sbl_anonymous_ip($q,$a,$q2,$a2);

		if($replycode == 0) {
			if($age = sbl_domain_age($q2, $a2)) {
				//echo '$age = '.$age."\n";
				if( $age < $settings['SBL']['min_age'] ) {
					$replycode = 3;
					sbl_blacklist_add($q->IP,'not old enough');
				}
			}
		} else {
			sbl_blacklist_add($q->IP,'no hostname');
		}
	}

	if ( $replycode == 0 ) {		// 0 = This IP has associated host or whitelisted.

		/*  What to return in "not-blocked" situation depends on your spam filter / mail server.
		    Usually, SBL verification only acts upon 127.0.0.x responses and ignores everything else.
		    This is something you'll need to find out in the documentation and/or run some tests.*/

		if( isset($q2) ) {			// Did we run sbl_anonymous_ip()? If we didn't $q2 and $a2 will not be set and cannot be used.

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

			if( sbl_hostname_contains_ip($q2,$a2) ) {
				$a->src = '$';		// To be verified
			} else {
				$a->src = '@';		// Allowed
			}

		} else {			// No, we did not run sbl_anonymous_ip(). This IP is whitelisted.

			$a->set_type('A');
			$a->AN['A']   = Array('1.1.1.1'   => Array ('ttl' => $settings['DNS']['TTL']));		// add A record to ANswer collection
			$a->AN['PTR'] = Array('whitelist' => Array ('ttl' => $settings['DNS']['TTL']));		// add PTR record to ANswer collection
			$a->src = '@';		// Allowed
		}

	} elseif ( $replycode == 3 ) {		// 3 = Blacklisted or there is no host/domain associated with this IP address - BLOCK IT

		$a->set_type('A');
		$a->AN['A']   = Array($settings['SBL']['return_ip'] => Array ('ttl' => $settings['DNS']['TTL']));	// add A [127.0.0.x] record to ANswer collection
		$a->AD['TXT'] = Array(                            0 => Array ('txt' => $settings['SBL']['txt']));	// add TXT record to ADditional collection
		$a->src       = '#';		// Blocked
		$replycode    = 0;		// change REPLYCODE to no-error
	}

	//sbl_test_ports($q);

	return $replycode;
}

function sbl_whitelist( $ip ) {
	/*
	  This rule checks database to see if IP address is whitelisted (not a spammer).
	*/
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "SELECT * FROM whitelist WHERE ip='$ip'";
		if ($result = mysqli_query($db,$sql)) {
		    //printf("$sql returned %d rows.\n", mysqli_num_rows($result));
		    if(mysqli_num_rows($result) > 0) {
			mysqli_free_result($result);
			return true;
		    }
		}
	}
	return false;
}

function sbl_blacklist( $ip ) {
	/*
	  This rule checks database to see if IP address is blacklisted (spammer).
	*/
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "SELECT * FROM blacklist WHERE ip='$ip'";
		if ($result = mysqli_query($db,$sql)) {
		    //printf("$sql returned %d rows.\n", mysqli_num_rows($result));
		    if(mysqli_num_rows($result) > 0) {
			mysqli_free_result($result);
			return true;
		    }
		}
	}
	return false;
}

function sbl_blacklist_add( $ip, $reason='' ) {
	/*
	  Add IP address to blacklist.
	*/
	global $settings, $db;

	if( $db = connect_db() ) {
		$sql = "REPLACE INTO blacklist(ip,source) VALUES ('$ip','sbl_lookup.php: ".$reason."')";
		return mysqli_query($db,$sql,MYSQLI_ASYNC);
	}
	return false;
}

function sbl_anonymous_ip( &$q, &$a, &$q2, &$a2 ) {
	/*
	  This rule checks if given IP address has a hostname associated with it. If not, returns 'A' with IP 127.0.0.2 followed by a TXT record.
	*/
	global $settings;
	//static $q2, $a2;

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

function sbl_hostname_contains_ip(&$q2,&$a2) {
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

function sbl_test_ports(&$q) {
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

function sbl_domain_age( &$q2, &$a2 ) {
/*
	Executes 'whois' for a domain in question, extracts domain creation date from the
	result, returns difference in days between domain creation date and now.
*/
	global $settings, $dns_cache;

	// do nothing if 'min_age' < 1 or is not set
	if(!isset($settings['SBL']['min_age']) || $settings['SBL']['min_age'] < 1) return false;

	$e = array_reverse(explode('.',key($a2->AN['PTR'])));
	$str_domain = $e[1].'.'.$e[0];

	// Check DNS cache for parameter 'age' added by previous lookup
	if( isset( $dns_cache['table'][$str_domain]['age'] )) {
		return $dns_cache['table'][$str_domain]['age'];
	}

	//echo '$ whois '.$str_domain."\n";
	exec('whois '.$str_domain, $output);

	foreach($output as $line) {
		switch(true) {
		case (stripos($line,'creation date:') !== false):
			$d = substr(trim($line),15);
			break;
		case (stripos($line,'created on:')    !== false):
			$d = substr(trim($line),12);
			break;
		case (stripos($line,'domain registration date:') !== false):
			$d = substr(trim($line),27);
			break;
		case (stripos($line,'created date:')  !== false):
			$d = substr(trim($line),14);
			break;
		case (stripos($line,'created:')       !== false):
			$d = substr(trim($line),10);
			break;
		case (stripos($line,'registered on:') !== false):
			$d = substr(trim($line),15);
			break;

		}
		if(isset($d)) break;
	}

	if(!isset($d)) {
		print_r($output);
		return false;
	}

	//echo $line."\n";
	$d = trim($d);

	if(date_parse($d)['error_count'] > 0) {
		$patterns = array(
			'/.*(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).*/' => '$1-$2-$3 $4:$5:$6',
			// add patterns and corresponding replacements as needed
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
		return $interval->days;
	} else {
		echo "sbl_domain_age() - can't convert '$line' to a date. You may want to add aditional pattern to reformat this value into a date string.\n";
		return false;
	}
}

?>