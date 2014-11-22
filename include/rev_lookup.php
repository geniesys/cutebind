<?php
function rev_lookup( &$q, &$a ) {	// Reverse-lookup an IP address (addr-to-name translation). Returns: int Error Code. Updates values in $cq object.
/*
	Search for a record in various places (order is important).
	$cq object contains all needed input information and output propeties that we need to update in response.
	$q->QTYPE specifes type of record that we are looking for (A, PTR).
*/
	global $settings;
	global $dns_cache;
	global $cache;	$cache = &$dns_cache['table'];	// update reference to inline cache hash-table. Somehow it doesn't point to the $dns_cache['table'] (?)
	global $table;

	$result;					// local var used to keep result of successful lookup before we put it back into $a->R_DOMAIN in the 2nd half of this function.
/*
	if ($q->QTYPE == 'PTR') {
		$q->QTYPE_INT = 0x01;
		$q->QTYPE     = 'A';
	}
*/
	if(       !isset($q->l_host) and isset($q->host) ) {				// if one of the hosts is missing - fix it using the other value
		$q->l_host = strtolower($q->host);
	} elseif( !isset($q->host)   and isset($q->l_host) ) {
		$q->host = $q->l_host;
	} elseif( !isset($q->l_host) and !isset($q->host) ) {
		log_error('[ERROR] rev_lookup() - Required property $q->host is not specified. Please specify before calling this function.');
		print_r($q);
		return 2;								// 2 = Internal server error
	}

	if( substr($q->l_host,-14) == '.in-addr.arpa.' ) {				// convert 4.3.2.1.in-addr.arpa. to 1.2.3.4
		$e = explode('.',$q->host);
		if(count($e) < 7) return 5;						// Mailformed IP - reject.
		$q->IP = $e[3].'.'.$e[2].'.'.$e[1].'.'.$e[0];
	} else {
		$q->IP = substr($q->l_host,0,-1);					// remove '.' at the end since the above also has no dot.
		$e = explode('.',$q->IP);
		if(count($e) < 4) return 5;						// Mailformed IP - reject.
		$q->host = $e[3].'.'.$e[2].'.'.$e[1].'.'.$e[0].'.in-addr.arpa.';	// fix the host name so that dns_get_record() can use it
		$q->l_host = $q->host;
	}

	if($settings['DEBUG']) echo "[DEBUG] rev_lookup() - Resolving '".$q->QTYPE."' record for '".$q->l_host."'\n";

	for($i=0; $i<4; $i++) {
		if( ! is_numeric($e[$i]) ) {
			if($settings['DEBUG']) echo "IP '".$q->IP."' is invalid (not a number).\n";
			return 5;
		}
		if( (int)$e[$i] > 255 ) {
			if($settings['DEBUG']) echo "IP '".$q->IP."' is invalid (out of range).\n";
			return 5;
		}
	}

	$a->REVERSE = TRUE;
/*
	if($dns_cache['DEBUG']) {
		echo 'Cached record for '.$q->IP."\t\t is ";
		if(isset($cache[$q->IP])) {
			echo "FOUND\n";
			echo 'Has [PTR] ? '.((isset($cache[$q->IP]['PTR'])) ? 'YES' : 'NO')."\n";
		} else {
			echo "NOT FOUND\n";
		}
		echo 'Cached record for '.$q->l_host."\t is ";
		if(isset($cache[$q->l_host])) {
			echo "FOUND\n";
			echo 'Has [PTR] ? '.((isset($cache[$q->l_host]['PTR'])) ? 'YES' : 'NO')."\n";
		} else {
			echo "NOT FOUND\n";
		}
	}
*/
	switch(true) {
	case (isset($table[$q->IP]['PTR'])):						// try internal (static) table
		$result['PTR'] = $table[$q->IP]['PTR'];
		$a->src = 'T';
		break;
	case (isset($cache[$q->IP]['PTR'])):						// try cache
		$result['PTR'] = $cache[$q->IP]['PTR'];
		$a->src = 'C';
		break;
	case (resolver($q,$a)):								// see if name resolution can be done via resolver() function
		//$result = $a->???;
		//if(isset($a->???)) {
		//    $a->src = 'R';
		//    dns_cache_add(array('ip'=>$q->IP,'type'=>'PTR','target'=>$a->???,'ttl'=>300) );
		//    break;
		//} else {
		//    echo '[ERROR] resolver() returned TRUE, but $a->??? was not set by resolver(). Why?'."\n";
		//    print_r($q);
		//}
		// !!! NO "break" here. We want to continue with "dns_get_record()" when resolver() has not found anything.

	case ($result = dns_get_record($q->l_host,DNS_PTR,$authns,$addtl)):		// this lookup needs to be done using '4.3.2.1.in-addr.arpa.' Function doesn't work using normal IPv4.

		if($settings['DEBUG']) echo "Result of dns_get_record($q->l_host,DNS_PTR): " && print_r($result);

		foreach($result as $record) {
			if($record['target'] == '' || $record['target'] == 'localhost') continue;	// these are bogus and invalid hostnames usually intended to trick spam filters
			if(dns_cache_add($record)) {
			    if($settings['DEBUG']) {
				echo 'Added this PTR record into cache: ';
				print_r($record);
				echo 'isset( $cache['.$q->IP.'][PTR] ) = '.isset($cache[$q->IP]['PTR']);
			    }
			 } else {
			 	return 5;
			 }
		}

		unset($result);				// Erase it. This $result reresents response from dns_get_record(). We will make new $result below based on our findings.

		$cache = &$dns_cache['table'];		// update reference to cache hash-table.

		//echo "We just added a PTR record for host ".$q->IP." to the cache. Lets see it ...\n";
		//print_r($cache[$q->IP]);

		if( isset($cache[$q->IP]['PTR']) ) {			// did we get the record we were looking for?
			$result['PTR'] = $cache[$q->IP]['PTR'];
			$a->src = 'L';					// "L" here because we did lookup before caching this record
		} else {
			$a->src = '-';
			return 3;					// 3 = Host/domain not found
		}

		break;

	default:
		$a->src = '-';
		return 3;						// 3 = Host/domain not found
	}

	if(! isset($result)) {
		echo "[ERROR] rev_lookup() -\$result is not set. Something is wrong. Need to debug it.\n";
		//$a->R_DOMAIN = null;
		$a->AN = null;
		return 2;						// 2 = Internal server error
	}

	$a->AN = $result;
	//echo 'rev_lookup(): - $result = '; print_r($result);

	//$a->R_DOMAIN = key($result);
	//if(is_array($a->R_DOMAIN)) {
	//    echo '$a->R_DOMAIN is an array. Why?'."\n";
	//    print_r($q);
	//}
	//if (substr($a->R_DOMAIN,-1) != '.') $a->R_DOMAIN .= '.';

	//$q->bin_host = _labels($a->R_DOMAIN);		// R_DOMAIN IS NO LONGER USED. DOING THIS WILL ERASE $bin_host 
	//if (substr($q->bin_host,-1) != "\x00") {$q->bin_host .= "\x00";}

	//if ($q->IP == '') return 3;					// Host/domain not found

	//if (isset($a->REVERSE) && $a->REVERSE) {
	//	$a->AN[] = $a->R_DOMAIN;
	//} else {
	//	$a->dest    = $q->IP;
	//}

	return 0;							// 0 = Successful
}

?>