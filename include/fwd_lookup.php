<?php
function fwd_lookup( &$q, &$a ) {	// Forward-lookup a record for a host or domain (name-to-addr translation). Returns: int Error Code. Returns corresponding records in $a->RDATA array.
/*
	Search for a record in various places (order is important).
	$q object contains all needed input information and output propeties that we need to update in response.
	$q->QTYPE specifes type of record that we are looking for (A, NS, MX, SOA, etc.).
*/
	global $settings;
	global $dns_cache;
	global $cache;	$cache = &$dns_cache['table'];	// update reference to inline cache hash-table. Somehow it doesn't point to the $dns_cache['table'] (?)
	global $table;

	$result;					// local var used to keep result of successful lookup before we put it back into $a->AN in the 2nd half of this function.

	if($settings['DEBUG']) echo "[DEBUG] fwd_lookup() - Resolving '".$q->QTYPE."' record for '".$q->l_host."'\n";

	if($q->QTYPE == 'ALL') {
		if      ( isset($table[$q->l_host]) ) {					// try static table
			$result = $table[$q->l_host];
			$a->src = 'T';
		} elseif( isset($cache[$q->l_host]) ) {					// try cache
			$a->src = 'C';
			if( count($cache[$q->l_host])==0 ) return 3;			// Recordset has no data - either a special record that indicates host/ip wasn't found or some sort of problem. In either case we cannot continue and must get out of here with code 3.
			$result = $cache[$q->l_host];
			unset($result[0]);						// Remove record expiration timestamp. This is not a resource record.
		} elseif( resolver($q,$a) ) {						// try resolver()
			//foreach( $q->IP as $ip) {
			//	dns_cache_add(array('host'=>$q->l_host,'type'=>$q->QTYPE,'ip'=>$q->IP,'ttl'=>$settings['DNS']['TTL']));	// cache it to reduce number of db queries
			//}
			//$result = $cache[$q->l_host];
			//unset($result[0]);						// Remove record expiration timestamp. This is not a record.
			$a->src = 'R';
		}
	} else {	// Looking for particular record type
		if      ( isset($table[$q->l_host][$q->QTYPE]) ) {			// try static table
			$result[$q->QTYPE] = $table[$q->l_host][$q->QTYPE];
			$a->src = 'T';
		} elseif( isset($cache[$q->l_host][$q->QTYPE]) ) {			// try cache
			$a->src = 'C';
			if( count($cache[$q->l_host][$q->QTYPE])==0 ) return 3;		// Recordset has no data - either a special record that indicates host/ip wasn't found or some sort of problem. In either case we cannot continue and must get out of here with code 3.
			$result[$q->QTYPE] = $cache[$q->l_host][$q->QTYPE];
		} elseif( $q->QTYPE == 'A'  and isset($cache[$q->l_host]['CNAME'])) {	// Question was for 'A'. I don't have 'A' but do have 'CNAME'
			if($settings['DEBUG']) echo "[DEBUG] fwd_lookup() - Retuning 'CNAME' in request for 'A' record.\n";
			$result['CNAME'] = $cache[$q->l_host]['CNAME'];
			$a->set_type('CNAME');
			$a->HAS_TARGETS = true;						// This is CNAME record. Will have to do recursive lookups.
			$a->src = 'C';
		} elseif( resolver($q,$a) ) {						// try resolver()
			//foreach( $q->IP as $ip) {
			//    dns_cache_add(array('host'=>$q->l_host,'type'=>$q->QTYPE,'ip'=>$q->IP,'ttl'=>$settings['DNS']['TTL']));	// cache it to reduce number of db queries
			//}
			//$result = $cache[$q->l_host][$q->QTYPE];
			$a->src = 'R';
		}
	}

	if(! isset($result) ) {		// none of the above returned any records
	    //echo  "No records for '$q->l_host' on this server. Executing external lookup...\n";
	    if( $result = dns_get_record($q->l_host,DNS_ALL,$authns,$addtl) ) {		// try external DNS lookup (get ALL records at once so that we don't have to repeat this excersize)
		//echo "Result of dns_get_record('$q->l_host',DNS_ANY) = ";print_r($result);
		//if(isset($authns)) echo "Authorative records = "; print_r($authns);
		//if(isset($addtl))  echo "Additional records  = "; print_r($addtl);

		// ----- Cache all records regardless of type asked in question -----
		// This loop adds each record into cache. You can modify or remove unwanted information before record is cached.
		// Keep in mind that dns_cache_add() converts 'host' and 'type' into associative array keys and then removes it from $record itself.
		// These properties must be present in all cases. Do not remove or alter it. 'class' is not used at this time.

		foreach($result as $record) {
			switch($record['type']) {		// CUSTOM RECORD HANDLER  - Allows you to handle particular types of records differently (before it is cached).
			case 'TXT':				// ['entries'][0] contains the same value as ['txt']. We don't need this duplicate value.
				if(count($record['entries']) == 1 && $record['txt']=$record['entries'][0]) unset($record['entries']);
				break;
			default:				// GENERIC RECORD HANDLER
				// No changes. All records are stored in similar manner. See examples at the end of this file.
			}
			if(!dns_cache_add($record)) return 5;
		}

		unset($result);						// Erase it. This $result reresents response from dns_get_record(). We will make new $result below based on our findings in cache.

		$cache = &$dns_cache['table'];				// update reference to cache hash-table.

		// ----- Check cache again to see if we got the record we were looking for -----

		if( isset($cache[$q->l_host]) ) {			// Do we have any records for this host?
		    if($q->QTYPE == 'ALL') {				// Asked for ANY?
			$result = $cache[$q->l_host];			// Return ALL we have.
			unset($result[0]);				// Except expiration timestamp. This is not a resource record.
			$a->src = 'L';					// "L" here because we just did lookup before caching this record.
		    } else {						// Otherwise, assume that Question was for particular record type.
			if( isset($cache[$q->l_host][$q->QTYPE]) ) {		// Do we have records of this type for this host?
			    $result[$q->QTYPE] = $cache[$q->l_host][$q->QTYPE];	// Return record of type that was asked for.
			    $a->src = 'L';				// "L" here because we did lookup before caching this record
			} elseif($q->QTYPE == 'A' && isset($cache[$q->l_host]['CNAME']) ) {	// Question was for 'A' but I have a 'CNAME' instead.
			    if($settings['DEBUG']) echo "[DEBUG] fwd_lookup() - Retuning 'CNAME' in request for 'A' record.\n";
			    $result['CNAME'] = $cache[$q->l_host]['CNAME'];
			    $a->set_type('CNAME');
			    $a->src = 'L';				// "L" here because we just did lookup before caching this record
			} else {
			    dns_cache_add(array('host'=>$q->l_host,'type'=>$q->QTYPE,'class'=>'IN'));	// add dummy record to indicate that host wasn't found and no further external lookups should be done until record expires
			    $a->src = '-';
			    return 3;					// 3 = Host/domain not found
			}
		    }
		} else {
		    dns_cache_add(array('host'=>$q->l_host,'type'=>$q->QTYPE,'class'=>'IN'));		// add dummy record to indicate that host wasn't found and no further external lookups should be done until record expires
		    $a->src = '-';
		    return 3;						// 3 = Host/domain not found
		}
	    } else {							// dns_get_record() did not find anything
		if($q->QTYPE != 'ALL') {				// ALL is not a type. It tell what records to search for (equivalent of *), but records of type 'ALL' don't exist.
			dns_cache_add(array('host'=>$q->l_host,'type'=>$q->QTYPE,'class'=>'IN'));	// add dummy record to indicate that host wasn't found and no further external lookups should be done until record expires
		}
		$a->src = '-';
		return 3;						// 3 = Host/domain not found
	    }
	}

	if(! isset($result)) {
		echo "[ERROR] fwd_lookup() -\$result is not set. Something is wrong. Need to debug it.\n";
		$a->AN = null;
		return 2;						// 2 = Internal server error
	}

	if(isset($result['A']) && count($result['A']) > 1) {		// Roundrobin is applicable only to 'A' records (IP addresses)
		$doRR = 0;						// Assume 0
		switch($a->src) {					// Check bit that corresponds to our source
		case 'T': $doRR = $settings['DNS']['RR'] & 1; break;	// Records were obtained from inline hash-table
		case 'C': $doRR = $settings['DNS']['RR'] & 2; break;	// Records were obtained from cache
		case 'R': $doRR = $settings['DNS']['RR'] & 4; break;	// from Resolver/DB
		case 'L': $doRR = $settings['DNS']['RR'] & 8; break;	// via ext. lookup
		}
		if($doRR) {						// if $doRR not 0
			$keys = array_keys($result['A']);		// get list of keys (IP's)
			shuffle($keys);					// shuffle this list
			foreach($keys as $k) $arr[$k] = $result['A'][$k];// make new array with different order
			$result['A'] = $arr;				// replace original 'A'
		}
	}

	$a->AN = $result;						// Save answer in $a->AN

	return 0;							// 0 = Successful
}
?>
