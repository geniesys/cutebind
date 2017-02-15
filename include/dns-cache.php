<?php
$dns_cache = array(				// DNS cache array
	'TTL'	=> 600,				// Default time for records to remain in cache (sec). Please not this is not the same as 'ttl' of a DNS record.
	'DIRTY'	=> TRUE,			// Flag indicating whether or not cache has been modified and needs to be put into shared memory. Keep default as TRUE to force initial write into shared memory.
	'DEBUG'	=> FALSE, 			// Turn debugger on/off. It prints additional debug messages related to cache operations.
	'table'	=> array(			// Hash-table
		'localhost.'	=> array(	// This will never be used because static record in $table always takes highrt priority. I just want to initialize this table with something. Do no worry. It will expire in 10 sec.
			time()+10,		// expires after this time (unix timestamp, see php time() function). To access this element use [0].
			'A'   => array('127.0.0.1' => array('ttl'=>10)),
			'AAAA'=> array('::1'       => array('ttl'=>10))
			),
		'127.0.0.1.'	=> array(	// This will never be used because static record in $table always takes highrt priority. I just want to initialize this table with something. Do no worry. It will expire in 10 sec.
			time()+10,		// expires after this time (unix timestamp, see php time() function). To access this element use [0].
			'PTR' => array('localhost' => array('ttl'=>10))
			)
		),
	);

$cache = &$dns_cache['table'];		// get reference to inline cache hash-table.

/*
echo "[DEBUG] ---------- TEST CACHE ----------\n";
print_r($cache);
echo "Adding 'host.example.tld.' to cache ...\n";
$cache['host.example.tld.'] = array(time(), 'A'=>array('1.2.3.4'=>array('ttl'=>10)),'NS'=>array('1.2.3.4'=>array('ttl'=>10)));
print_r($cache);
echo "[DEBUG] --------------------------------\n";
*/

function dns_cache_add($record) {
	/*
	Add record to $dns_cache['table'] array.
	Returns:  void
	Usage  : dns_cache_add($record);
	$record (which is an associative array) must contain 'host','type', and 'class' in all cases. Other properties are as applicable.
	Any $record created by means other than dns_get_record() (virtual records or from DB) must be identical to what dns_get_record()
	would return. See help for this function if you have any questions.
	*/
	global $settings, $dns_cache;

	// Converts 'host' and 'type' into associative array keys and remove it from $record
	// because it duplicates what's already know.

	$t = $record['type'];
	$h = $record['host'];
	$c = $record['class'];

	if($t == 'PTR') {
/*
Logic needs to be rivised here. Must also account for 7-element array where 2nd is like 0/24
I should look at the $record again and see if I can translate canonical name to actual .in-addr.arpa

Examples:

nslookup
> set debug=on
> set type=PTR
> 135.96.8.207.in-addr.arpa.

Non-authoritative answer:
135.96.8.207.in-addr.arpa       canonical name = 135.0/24.96.8.207.in-addr.arpa
135.0/24.96.8.207.in-addr.arpa  name = multi125.postfix.bmsend.com

> 240.237.102.38.in-addr.arpa.
Non-authoritative answer:
240.237.102.38.in-addr.arpa     canonical name = 240.192/26.237.102.38.in-addr.arpa
240.192/26.237.102.38.in-addr.arpa      name = lax-virtualmin-01.rezitech.net

Log:
PTR record contains invalid IPv4 address 102.237.192/26.240
A 240.237.102.38.sbl.geniesys.net. -> A 38.102.237.240, PTR lax-virtualmin-01.rezitech.net
$h = 102.237.192/26.240	 Problem #1 - I'M MISSING 38.

Forward lookup:	lax-virtualmin-01.rezitech.net	-> 1) A     38.102.237.240
Reverse lookup: 240.237.102.38.in-addr.arpa.    -> 1) CNAME 240.192/26.237.102.38.in-addr.arpa
                                                   2) name = lax-virtualmin-01.rezitech.net
------------
38.102.237.192/26.240

38.102.237.192/26 -> 38.102.237.192 ... 38.102.237.255 (64)
38.102.237.240/26 -> 38.102.237.192 ... 38.102.237.255 (64)
38.102.237.0/26   -> 38.102.237.0   ... 38.102.237.63  (64)

219.55.80/28.91
219.55.80.91/28 -> 219.55.80.80 ... 219.55.80.95 (16)
219.55.80.0/28  -> 219.55.80.0  ... 219.55.80.15 (16)

*/
/*	This won't work. I can't save CIDR-notated record (or whatever else might CNAME be) "as is" because consequent lookup will never find it.
	It actually causes IP that has associated host to be blacklisted with "Anonymous IP" reason.

		$h = str_replace('.in-addr.arpa','',$h);
		$h = str_replace('.in-addr-servers.arpa','',$h);
		$h = implode('.',array_reverse(explode('.',$h)));
		print_r($record);
		echo "\$h = $h\n";
*/
		$patterns = array(
			'/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$/'				=> '$4.$3.$2.$1',
			'/^(\d{1,3})\.(\d{1,3})(\/\d{1,2})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$/'	=> '$6.$5.$4.$1'
		);

//		echo "\$h = $h\n";
		foreach($patterns as $p => $r) {
			//echo '$p = '.$p.', $r = '.$r."\n";
			$x = preg_filter($p, $r, $h);
			//echo '$x = '.$x."\n";
			if($x) {
				//$h = $x;
				//print_r(cidrToRange($h));
				//print_r(cidrToRange('38.102.237/26.240'));
				break;
			}
		}

/*
		$e = explode('.',$h);
		if(count($e) == 6) {
			$h = $e[3].'.'.$e[2].'.'.$e[1].'.'.$e[0];
		} elseif(count($e) == 7 && strpos($e[1],'/') !== false) {
			$h = $e[4].'.'.$e[2].'.'.$e[1].'.'.$e[0];
		} else {
		//if(count($e) != 6) {
*/
		if($x) {
			$h = $x;
		} else {
			log_error('dns_cache_add() - PTR record contains invalid IPv4 address '.$h);
			if($settings['DEBUG']) print_r($record);
			// attempting to repair this record
			$e = explode('.',$h);
			foreach($e as $k => $v) {
				//echo '$k='.$k.', $v='.is_numeric($v)."\n";
				if(!is_numeric($v) || (int)$v > 254) unset($e[$k]);
			}
			if(count($e) == 4) {
				$h = implode('.',array_reverse($e));
			} else {
				return false;
			}
		}

	} elseif( substr($h, -1) !== '.' ) {
		$h .= '.';
	}

	unset($record['type']);
	unset($record['host']);
	unset($record['class']);		// Disable this line if you want to keep track of classes.

	$dns_cache['table'][$h][0] = time()+$dns_cache['TTL'];			// internal record exp. time always goes into [0]

/*
	if($t != 'A' and $t != 'NS' and $t != 'AAAA' and $t != 'MX' ) {
	  echo "dns_cache_add('$host_or_ip',\$record) : where \$record = ";
	  print_r($record);
	}
*/
	switch(true) {
	case isset($record['ip']):
		$key = $record['ip'];
		unset($record['ip']);
		$dns_cache['table'][$h][$t][$key] = $record;

		/*
		  It is possible to create PTR records at the same time.
		  I'm not sure how usefull this functionality could be since chances of having
		  to resolve the same entity in both, forward and reversed way, are kinda slim.
		  Anyways, this is how it can be done:

		$dns_cache['table'][$key][0] = time()+$dns_cache['TTL'];
		$dns_cache['table'][$key]['PTR'][$h] = array('ttl' => $record['ttl']);
		echo "dns_cache_add() - I also created a PTR record for '".$key."'\n";
		print_r($dns_cache['table'][$key]);
		*/
		break;
	case isset($record['target']):
		$key = $record['target'];
		unset($record['target']);
		$dns_cache['table'][$h][$t][$key] = $record;
		break;
	case isset($record['ipv6']):
		$key = $record['ipv6'];
		unset($record['ipv6']);
		$dns_cache['table'][$h][$t][$key] = $record;
		break;
	case isset($record['mname']):		// SOA
		$key = $record['mname'];
		unset($record['mname']);
		$dns_cache['table'][$h][$t][$key] = $record;
		break;
	case (count($record)==0):				// This is special record that has no data (empty array). Such record indicates host/ip has not been found.
		$dns_cache['table'][$h][$t] = $record;		// At his point, $record should be an empty array. We add it w/out [] (i.e. not numerically indexed)
		$dns_cache['table'][$h][0] = time()+30;		// Make such records expire faster. 1/10th of the default = 30 sec (TBD)
		break;
	default:
		$dns_cache['table'][$h][$t][] = $record;	// (!) because of [] all values are added as an array, even if there is the only one value.
	}
/*
	if($t != 'A' and $t != 'NS' and $t != 'AAAA' and $t != 'MX' ) {
	  echo "After it has been modifed...\n";
	  print_r($record);
	  echo "And all types of records for this host look like...\n";
	  print_r($dns_cache['table'][$h]);
	}
*/
	$dns_cache['DIRTY'] = TRUE;
	return true;
}

function dns_cache_add_raw($records) {
	/*
	Add one or more record to $dns_cache['table'] array or replace existing onece.
	(!) This function skipps all conversions and assumes that $record is already an associative array and has proper structure.
	$record must be passed as an array even if it contains only one record. This is done to preserve the top-level key.
	Returns:  void
	Usage  : dns_cache_add_raw([$record1, $record2, ...]);

	$record example #1:

	[resolver.example.tld.] => Array (
		[A] => Array (
			[12.34.56.78] => Array (
				[ttl] => 60
			)
		)
	)


	$record example #2:

	[127.0.0.1.] => Array (
		[PTR] => Array (
			[localhost] => Array (
				[ttl] => 10
			)
		)
	)

	*/

	global $settings, $dns_cache;

	foreach($records as $key => $record) {
		$record[0] = time()+$dns_cache['TTL'];			// internal record exp. time always goes into [0]
		$dns_cache['table'][$key] = $record;
	}

	$dns_cache['DIRTY'] = TRUE;
	return true;
}

function dns_cache_put() {
	/*
	Writes JSON-encoded $dns_cache array into shared memory.
	Maintains the size of the cache by:
	  a) Removing expired records;
	  b) Removing oldest unexpired record(s) if new table won't be able to fit into its shared memory segment;
	  c) Dynamicly agjusts record expiration time based on shared memory usage;
	Returns the size of the written data, or FALSE on failure.
	Please note: Some of the [DEBUG] messages are commented out to reduce screen output. These messages are not really important.
	Enable it only if you need to debug this particular function.
	*/

	global $dns_cache;
	global $ipc;

	if( ! $dns_cache['DIRTY'])	return TRUE;			// cache has not been modified - nothing needs to be done, so exit now with success status
	if( ! isset($ipc))		return FALSE;			// $ipc is not defined - will not be able to write

	$cache  = &$dns_cache['table'];					// get pointer to the inline cache hash-table.

	//if($dns_cache['DEBUG']) echo '[DEBUG] dns_cache_put() - Removing expired records...'."\n";
	while( $record = current($cache) ) {
		//if($dns_cache['DEBUG']) echo "[DEBUG] ".key($cache)."\t".'expires in '.($record[0]-time())." sec.\n";
		if(time() > $record[0]) unset($cache[key($cache)]);	//$cache[key($cache)] = null;	// erase current record
		next($cache);
	}
	//if($dns_cache['DEBUG']) echo '[DEBUG] Done removing expired records'."\n";

	$dns_cache['DIRTY'] = FALSE;					// Change to False because this is how we want to save it in the shared memory

	$x = json_encode($dns_cache,JSON_FORCE_OBJECT);

	while( strlen($x) > DNS_CACHE_SIZE ) {				// (!) make sure we are not exceeding the size of shared memory used for cache

	    if($dns_cache['DEBUG']) echo '[DEBUG] DNS cache exceeds size of its shared memory segment. I have to remove one or more records'."\n";

	    $oldest = time()+900;					// Initialize with some time in the future. We'll be using this variable to find record that expires soonest.

	    reset($cache);
	    while( $record = current($cache) ) {
		//if($dns_cache['DEBUG']) echo '[DEBUG] Evaluating '.key($cache).' : '.$record[0]."\n";
		if( $record[0] < $oldest ) {
		    $oldest = $record[0];
		    $key    = key($cache);				// remember the key of our oldest record
		}
		next($cache);
	    }

	    if(isset($key)) {
		//if($dns_cache['DEBUG']) echo 'Oldest record is '.$key."\n";
		unset($cache[$key]);					// I have no choice but to erase oldest record to make this fit into our memory
	    } else {
		array_shift($cache);					// if the above logic didn't work for some reason, this is a backup solution
	    }

	    if($dns_cache['TTL'] > 300) $dns_cache['TTL'] = 300;	// Since we are in kinda emergency situation, reset record expiration time back to default value without waiting for check_cache_exp() to do this.

	    $x = json_encode($dns_cache,JSON_FORCE_OBJECT);
	}

	$x = str_pad($x,DNS_CACHE_SIZE,"\x00",STR_PAD_RIGHT);
	return shmop_write($ipc['dns-cache'],$x,0);
}

function dns_cache_get() {
	/*
	Reads JSON-encoded array from shared memory, decodes it, and updates $dns_cache object if decoding was successful.
	Returns  TRUE | FALSE.
	Usage: bool = dns_cache_get()
	*/
	global $dns_cache;
	global $ipc;

	if(!isset($dns_cache)) {
	    log_error('[DEBUG] dns_cache_get() - $dns_cache is not set');
	    return FALSE;
	}

	if(!isset($ipc)) {
	    log_error('[DEBUG] dns_cache_get() - $ipc is not set');
	    return FALSE;
	}

	$i = 0;
	while( ! $s = shmop_read($ipc['dns-cache'],0,DNS_CACHE_SIZE) ) {
		$i++;
		if($i > 2) {
			log_error('[DEBUG] dns_cache_get() - Failed to read from shared memory after '.$i.' attempts.');
			return FALSE;
		}
		usleep(100000);
	}

	$s = rtrim($s);
	$x = json_decode($s,true);

	switch (json_last_error()) {
        case JSON_ERROR_NONE:
	    $dns_cache = $x;
	    return TRUE;
	    break;
        case JSON_ERROR_DEPTH:
            echo '[ERROR] dns_cache_get().json_decode() - Maximum stack depth exceeded'."\n";
	    break;
        case JSON_ERROR_STATE_MISMATCH:
            echo '[ERROR] dns_cache_get().json_decode() - Underflow or the modes mismatch'."\n";
	    break;
        case JSON_ERROR_CTRL_CHAR:
            echo '[ERROR] dns_cache_get().json_decode() - Unexpected control character found'."\n";
            echo $s."\n";
	    break;
        case JSON_ERROR_SYNTAX:
            echo '[ERROR] dns_cache_get().json_decode() - Syntax error, malformed JSON'."\n";
            echo $s."\n";
	    break;
        case JSON_ERROR_UTF8:
            echo '[ERROR] dns_cache_get().json_decode() - Malformed UTF-8 characters, possibly incorrectly encoded'."\n";
	    break;
        default:
            echo '[ERROR] dns_cache_get().json_decode() - Unknown error';
	    break;
	}
	return FALSE;
}

function cache_DTA($interval) {			// Dynamic record expiration time agjustment. You can disable this feature in $schedule if such functionality is not desired. 

	global $ipc;
	global $dns_cache;

	$s = rtrim(shmop_read($ipc['dns-cache'],0,DNS_CACHE_SIZE));
	$i = strlen($s);

	if(! dns_cache_get()) {				// Load/reload cache from shared memory
	      echo "[ERROR] check_cache_exp() - Unable to load/reload cache from shared memory\n";
	}

	if      ( $i > DNS_CACHE_SIZE * 0.80 ) {		// if cache uses over 80% of its allocated memory...
	    if($dns_cache['TTL'] >  60) {
		$dns_cache['TTL'] = (int)($dns_cache['TTL'] * 0.9);	// make records expire 10% faster, but no less than 60 sec.  (5% of the default TTL of 300 sec)
		$x = json_encode($dns_cache,JSON_FORCE_OBJECT);
		if($dns_cache['DEBUG']) echo '[DEBUG] Cache uses > 80% of its allocated memory. Decreasing TTL by 10% to '.$dns_cache['TTL']." sec.\n";
	    }
	} elseif( $i < DNS_CACHE_SIZE * 0.20 ) {		// if cache uses less than 20% of its allocated memory...
	    if($dns_cache['TTL'] < 546) {
		$dns_cache['TTL'] = (int)($dns_cache['TTL'] * 1.1);	// make records expire 10% slower, but no more than 600 sec. (200% of the default TTL)
		$x = json_encode($dns_cache,JSON_FORCE_OBJECT);
		if($dns_cache['DEBUG']) echo '[DEBUG] Cache uses < 20% of its allocated memory. Increasing TTL by 10% to '.$dns_cache['TTL']." sec.\n";
	    }
	}

	if($dns_cache['DEBUG']) echo "[DEBUG] Cache: ".((int)DNS_CACHE_SIZE/1024).' KB; '.count($dns_cache['table']).' hosts, '.$i.' bytes, '.round($i*100/DNS_CACHE_SIZE,2).'% usage; TTL '.$dns_cache['TTL']." sec.\n";

	if(isset($x)) {
		$x = str_pad($x,DNS_CACHE_SIZE,"\x00",STR_PAD_RIGHT);
		return shmop_write($ipc['dns-cache'],$x,0);
	}

	return true;
}

/*
Examples of various records in the cache:

	[gmail.com.] =>  Array(	0     => 1406464494,							// Record expiration time (not a DNS record)
				[MX]  => Array(	[alt2.gmail-smtp-in.l.google.com] => Array (		// MX records
								[ttl] => 4
								[pri] => 20
							),
						[alt1.gmail-smtp-in.l.google.com] => Array (
								[ttl] => 4
								[pri] => 10
							)
					      ),

				[A]  => Array(	[173.194.37.86] => Array (				// IPv4 records
								[ttl]  => 5
							),
						[173.194.37.85] => Array (
								[ttl]  => 5
							)
					    ),
			      
				[AAAA]=> Array([2607:f8b0:4002:802::1015] => Array (			// IPv6 records
								[ttl]  => 4
							),
						[2607:f8b0:4002:802::1016] => Array (
								[ttl]  => 4
							)
					    ),

				[TXT] => Array (	// Multiple records are allowed as well as multiple lines per each record.
					[0] => Array (
						[ttl] => 3600
						[txt] => Record 0 - Line 1pRecord 0 - Line 2XRecord 0 - Line 3
						[entries] => Array (						// Cached record will include [entries] array
								[0] => Record 0 - Line 1
								[1] => Record 0 - Line 2
								[2] => Record 0 - Line 3
								)
						)
					[1] => Array (
						[ttl] => 600
						[txt] => v=spf1 a mx include:mailhop.org -all
						[entries] => Array (						// Cached record will NOT include [entries] array
								[0] => v=spf1 a mx include:mailhop.org -all
								)
						)
					[3] => Array (
						[ttl] => 5
						[txt] => http://www.spamhaus.org/sbl/query/SBLCSS
						[entries] => Array (						// Cached record will NOT include [entries] array
								[0] => http://www.spamhaus.org/sbl/query/SBLCSS
								)
						)
					)
			      ),
	[74.125.21.18] => Array(0     => 1406464494,							// Record expiration time (not a DNS record)
				'PTR' => Array (
						'yv-in-f18.1e100.net' => Array('ttl' => 42927)
					  )
			  )
			  
Example of positive response (host is listed) from bl.spamcop.net
Array
(
    [0] => Array
        (
            [host] => 203.63.137.41.bl.spamcop.net
            [class] => IN
            [ttl] => 5
            [type] => A
            [ip] => 127.0.0.2
        )

    [1] => Array
        (
            [host] => 203.63.137.41.bl.spamcop.net
            [class] => IN
            [ttl] => 5
            [type] => TXT
            [txt] => Blocked - see http://www.spamcop.net/bl.shtml?41.137.63.203
            [entries] => Array
                (
                    [0] => Blocked - see http://www.spamcop.net/bl.shtml?41.137.63.203
                )
        )
)

*/
?>