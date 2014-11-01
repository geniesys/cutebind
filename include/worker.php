<?php
require_once 'core-date.php';		// Date/Time functions.
require_once 'core-bytes.php';		// Various conversion and parsing functions to work with DNS packets.
require_once 'class_QuestionAnswer.php';// Question and Answer object definitions.
require_once 'fwd_lookup.php';		// Forward lookup resolver.
require_once 'rev_lookup.php';		// Reverse lookup resolver.
require_once 'sbl_lookup.php';		// Spam Block List (SBL) resolver.

require_once COREBIND_ROOT.'static_resolution_table.php';

$QTYPES = array(
	  1 => 'A'	,   2 => 'NS'	,   3 => 'MD'		,   4 => 'MF'	,   5 => 'CNAME',
	  6 => 'SOA'	,   7 => 'MB'	,   8 => 'MG'		,   9 => 'MR'	,  10 => 'RR',
	 11 => 'WKS'	,  12 => 'PTR'	,  13 => 'HINFO'	,  14 => 'MINFO',  15 => 'MX',
	 16 => 'TXT'	,  17 => 'RP'	,  18 => 'AFSDB'	,  19 => 'X25'	,  20 => 'ISDN',
	 21 => 'RT'	,  22 => 'NSAP'	,  23 => 'NSAP-PTR'	,  24 => 'SIG'	,  25 => 'KEY',
	 26 => 'PX'	,  27 => 'GPOS'	,  28 => 'AAAA'		,  29 => 'LOC'	,  30 => 'NXT',
	 31 => 'EID'	,  32 => 'NIMLOC', 33 => 'SRV'		,  34 => 'ATMA'	,  35 => 'NAPTR',
	 36 => 'KX'	,  37 => 'CERT'	,  38 => 'A6'		,  39 => 'DNAME',  40 => 'SINK',
	 41 => 'OPT'	,  42 => 'APL'	,  43 => 'DS'		,  44 => 'SSHFP',  45 => 'IPSECKEY',
	 46 => 'RRSIG'	,  47 => 'NSEC'	,  48 => 'DNSKEY'	,  49 => 'DHCID',  50 => 'NSEC3',
	 51 => 'NSEC3PARAM'		,  55 => 'HIP'		,  99 => 'SPF'	,
	100 => 'UINFO'	, 101 => 'UID'	, 102 => 'GID'		, 103 => 'UNSPEC',249 => 'TKEY',
	250 => 'TSIG'	, 251 => 'IXFR'	, 252 => 'AXFR'		, 253 => 'MAILB',
	254 => 'MAILA'	, 255 => 'ALL'	,32768=> 'TA'		,32769=> 'DLV',	    0 => 'UNK'
	);

$QTYPES = $QTYPES + array_flip($QTYPES);	// append reversed version of the above ($QTYPES['A'] => 1). Used for string to int translation. Do not use array_merge() function!

$QCLASSES = array(
	1   => 'IN',
	3   => 'CH',
	255 => 'ANY',
	);

$QCLASSES = $QCLASSES + array_flip($QCLASSES);	// append reversed version of the above ($QCLASSES['IN'] => 1). Used for string to int translation. Do not use array_merge() function!


function worker_sighandler($signo) {
	global $settings;
	global $dns_cache;

	static $signals = array(
		SIGTERM => 'SIGTERM',
		SIGABRT => 'SIGABRT',
		SIGINT  => 'SIGINT',			// catches Ctrl+C
		SIGKILL => 'SIGKILL',
		SIGUSR1 => 'SIGUSR1',
		SIGUSR2 => 'SIGUSR2 (Re-open logs)',
		SIGHUP  => 'SIGHUP (Debugger ON/OFF)'	// (Ping-pong)
		);

	if($settings['DEBUG']) echo "Worker (pid:".getmypid().") caught signal $signals[$signo].\n";

	switch($signo) {
	case SIGUSR1:			// Caught fullstatus-report
		break;
	case SIGUSR2:			// Caught reopen logs
		log_access('',TRUE);
		log_error('',TRUE);
		break;
	case SIGHUP:			// Caught status-check
		$settings['DEBUG']  = !$settings['DEBUG'];
		$dns_cache['DEBUG'] = !$dns_cache['DEBUG'];
		break;
	default:
	    if($signo == SIGTERM || $signo == SIGABRT || $signo = SIGINT) {
		if(! defined('TERMINATED')) define('TERMINATED',TRUE);
	    }
	}
}

function run_worker($wtype = '') {
	global $settings;
	global $zmap;
	global $dns_sockets;
	global $ipc;
	global $ipc_keys;
	global $table;
	global $QTYPES;
	global $QCLASSES;
	global $dns_cache;
	$q_counter = 0;
	$hash_table_offset = (int) $settings['maxDNSworkers'];		// 2nd part of dns-status-map starts at offset equal to maxDNSworkers (1st part is 1 byte per worker)
	$hash_table_length = (int) $settings['maxDNSworkers']*16;	// The length of this 2nd part equal to 16*maxDNSworkers (16 bytes per worker)

	if (!isset($zmap[$wtype])) $zmap[$wtype] = array();
	$zinfo = array(-1,time(),sizeof($zmap[$wtype]));
	$pid = pcntl_fork();
	if ($pid == -1) {
		die('could not fork');
	} elseif ($pid) {		// we are the master
		$zinfo[0] = $pid;
		$zmap[$wtype][] = $zinfo;
		return;
	}
	$zinfo[0] = getmypid();
/*
	$zinfo = Array(
		[0] => 22538		- this process id
		[1] => 1406707463	- time started
		[2] => 6		- worker number (starting with 0)
		)
*/

	cli_set_process_title('cutebind: worker process');     // we are the worker
	pcntl_signal(SIGTERM,'worker_sighandler');
	pcntl_signal(SIGHUP ,'worker_sighandler');
	pcntl_signal(SIGUSR1,'worker_sighandler');
	pcntl_signal(SIGUSR2,'worker_sighandler');
/*
	// Init database connection (each worker uses its own connection)
	if(isset($settings['mysql']['host'])) {
	    echo '[INIT] Connecting to MySQL server '.$settings['mysql']['host']." ... ";
	    $db = connect_db();
	    if($db) {
		echo "OK\n";
	    } else {
		echo "FAILED\n";
		echo mysqli_connect_error()."\n";
		echo "All functions that require database access will not be available.\n";
	    }
	}
*/
    while (TRUE)
    {
	//pcntl_signal_dispatch();

	if(defined('TERMINATED')) {
		shmop_delete($ipc['dns-status-map']);	// delete only. do not close - other workers may still be accessing it. Master will take care of it.
		shmop_delete($ipc['dns-q-counter']);
		shmop_delete($ipc['dns-cache']);
		exit(0);
	}

	$read = $dns_sockets;
	$num = @stream_select($read,$write = NULL,$except = NULL,0,200000);

	if ($num === 0) {
		continue;
	} elseif(FALSE === $num)  {	// Error.
//		echo '[ERROR] run_worker() (pid:'.$zinfo[0].') - stream_select() returned an error. Process is terminated.'."\n";
//		shmop_delete($ipc['dns-status-map']);	// delete only. do not close - other workers may still be accessing it. Master will take care of it.
//		shmop_delete($ipc['dns-q-counter']);
//		shmop_delete($ipc['dns-cache']);
//		exit(1);	// TURNS THIS PROCESS INTO A ZOMBIE UNTIL SIGTERM IS RECEIVED
		continue;
	}

	$data = stream_socket_recvfrom($bind = $read[0],1024,0,$peer);

	if (($data === '') || ($data === FALSE)) continue;

	$time = microtime(true);

/*	// Enable this to see raw request data
	if($settings['DEBUG']) {
	    echo "\n-------------------------------- REQUEST ----------------------------------\n";
	    hex_dump($data);
	    echo "---------------------------------------------------------------------------\n";
	}
*/
	shmop_write($ipc['dns-status-map'],"\x01",$zinfo[2]);	// I'm Busy
	++$q_counter;
	shmop_write($ipc['dns-q-counter'],_dword($q_counter),$zinfo[2]*4);

	$qinfo = array();
	$qinfo['id']        = _get_word($data);
	$bitmap             = getbitmap(_get_byte($data));
	$qinfo['QR']        = $bitmap[0];
	$qinfo['OPCODE']    = bindec(substr($bitmap,1,4));	// $bitmap parameter was missing?
	$qinfo['AA']        = $bitmap[5];
	$qinfo['TC']        = $bitmap[6];
	$qinfo['RD']        = $bitmap[7];
	$bitmap             = getbitmap(_get_byte($data));
	$qinfo['RA']        = $bitmap[0];
	$qinfo['Z']         = substr($bitmap,1,3);
	$qinfo['RCODE']     = bindec(substr($bitmap,4,4));
	$qinfo['QDCOUNT']   = _get_word($data);
	$qinfo['ANCOUNT']   = _get_word($data);
	$qinfo['AUCOUNT']   = _get_word($data);
	$qinfo['ADCOUNT']   = _get_word($data);
	$qinfo['REPLYCODE'] = 0;
	$qinfo['AA']        = 1;				// why AA gets overwritten here?

	$e = explode(':',$peer);
	$qinfo['peer_ip']   = $e[0];				// used in GeoIP resolver()
	$qinfo['peer_port'] = $e[1];

	$answer             = '';

	//var_dump($qinfo);
	if ($qinfo['QR'] == '0')				// Query
	{
	    for ($qn = 0; $qn < $qinfo['QDCOUNT']; ++$qn)
	    {
		$q = new Question($data);
		//print_r($q);
		$a = new Answer($q);
		//print_r($a);

		if($settings['DEBUG']) echo "[DEBUG] run_worker() - Received  '".$q->QTYPE."' query  for '".$q->l_host."'\n";

		$hash = md5($q->host.$q->QTYPE,true);		// 16-byte binary hash of the host+q_type being resolved
		$i = 0;
		while($i < 100) {
			$tmp = shmop_read($ipc['dns-status-map'],$hash_table_offset,$hash_table_length);
			//echo "[DEBUG] ------ dns-status-map -----\n";
			//hex_dump($tmp);
			if( strpos($tmp,$hash) === false ) {
				if($i==0) {
					//echo "Nobody else is resolving this\n";
					shmop_write($ipc['dns-status-map'],$hash,($hash_table_offset+$zinfo[2]*16));	// Tell other workers what I am resolving.
				} else {
					if($settings['DEBUG']) echo "[DEBUG] run_worker() - Another worker has finished resolving '$q->QTYPE' for '$q->host'. \$i=$i, pid=$zinfo[0]\n";
				}
				break;
			} else {
				if($settings['DEBUG'] && $i==0) echo "[DEBUG] run_worker() - Another worker is already resolving '$q->QTYPE' for '$q->host'. I will wait.\n";
				usleep(100000);
				$i++;
			}
			if($settings['DEBUG'] && $i==100) echo "[DEBUG] run_worker() - Timeout exceeded. pid=$zinfo[0] is continuing with normal resolution.\n";
		}

		// Load/reload cache from shared memory before each new resolution
		if(!dns_cache_get()) echo "[ERROR] Unable to load/reload cache from shared memory.\n";

		if( strpos($q->l_host,$settings['SBL']['hostmatch']) ) {	// trigger SBL processing only when the hostname contains string specified in $settings['SBL']['hostmatch']. See README.txt
			$qinfo['REPLYCODE'] = sbl_lookup($q,$a);
		} elseif (($q->QTYPE == 'PTR') || ($qinfo['OPCODE'] == '1') || (substr($q->l_host,-14) == '.in-addr.arpa.')) {
			$qinfo['REPLYCODE'] = rev_lookup($q,$a);
		} else {
			$qinfo['REPLYCODE'] = fwd_lookup($q,$a);
		}

		if( $settings['DEBUG'] ) {
			switch($qinfo['REPLYCODE']) {
			case 0:
			//	switch($a->src) {
			//	case 'T': echo "[DEBUG] Resolved using internal static table.\n";	break;
			//	case 'C': echo "[DEBUG] Resolved using cache.\n";			break;
			//	case 'R': echo "[DEBUG] Resolved using resolver().\n";			break;
			//	case 'L': echo "[DEBUG] Resolved using lookup.\n";			break;
			//	case '@': echo "[DEBUG] SPAM Check - PASS.\n";				break;
			//	case '#': echo "[DEBUG] SPAM Check - BLOCKED.\n";			break;
			//	case '-': echo "[ERROR] REPLYCODE=0 but SRC flag says nothing found\n";	break;
			//	case '?': echo "[ERROR] REPLYCODE=0 but SRC flag wasn't set.\n";	break;
			//	}
				break;
			case 1: echo "[DEBUG] Unable to resolve - Query packet error.\n";	break;
			case 2: echo "[DEBUG] Unable to resolve - Internal server error.\n";	break;
			case 3: echo "[DEBUG] Unable to resolve - Host/domain/ip not found.\n";	break;
			case 4: echo "[DEBUG] Unable to resolve - Not implemented.\n";		break;
			case 5: echo "[DEBUG] Unable to resolve - Query rejected by server.\n";	break;
			}
		}

		if (($qinfo['REPLYCODE'] == 0) || $qinfo['REPLYCODE'] == 3 || ($qinfo['REPLYCODE'] == 4)) {

			// Original Question section is returned regardless of number of answers.
			$answer .= $q->bin_host;
			$answer .= _word($q->QTYPE_INT );
			$answer .= _word($q->QCLASS_INT);

			if( count($a->AN) > 0 ) {

				$answer .= $a->get_data('AN');
				$qinfo['ANCOUNT'] = count($a->AN);	// update ANCOUNT with number of answers

				/*
				CNAME answers must include corresponding IP's as additional ANSWER records in which case $qinfo['ANCOUNT']++;
				SRV, MX, and NS answers must include corresponding IP's as ADDITIONAL records in which case $qinfo['ADCOUNT']++;
				ADDITIONAL records must follow ANSWER records. Structure of these records is identical.
				Client interprets ANCOUNT and ADCOUNT to find where the split point is and I believe, also to validate
				structure of the response.
				*/
				$a2 = $a;	// make a copy of $a
				while( count($a2->AN) and $a2->HAS_TARGETS ) {
				    if($settings['DEBUG']) echo "[DEBUG] run_worker() - Evaluating answer for aditional recursive resolutions.\n";
				    //echo '$a2->AN = '; print_r($a2->AN);
				    foreach( $a2->AN as $type => $recordset ) {
		    			if($type == '0') continue;				// Never mind. This is record expiration timestamp.
					foreach( $recordset as $key => $record ) {
					    if($settings['DEBUG']) echo "[DEBUG] run_worker() - Resolving '".$key."'\n";
					    $q2 = new Question;					// partial initialization - just set a few properties that fwd_lookup() actually uses
					    $q2->host   = $key.'.';
					    $q2->l_host = strtolower($q2->host);
					    $q2->set_type('A');
					    $q2->set_class('IN');

					    $a2 = new Answer($q2);

					    if( fwd_lookup($q2,$a2) == 0 ) {			// try to resolve
						//echo 'Got successful status code from fwd_lookup(). Answer contains '.count($a2->AN)." record(s).\n";
						//print_r($a2->AN);
						$answer .= $a2->get_data();
						if( in_array($a2->QTYPE,array('A','AAAA','CNAME') ) ) {
							// in case of CNAME, additional IP's found follow the CNAME answer itself and
							// are part of ANSWER portion of the response.
							$qinfo['ANCOUNT'] += $a2->count();
						} else {
							// for other records - I'm not sure. Need to test further.
							// For now, everything else goes into ADDITIONAL portion of the response.
							// Note that there is no difference in structure of each answer. Client uses
							// ANCOUNT and ADCOUNT counters to find out where ADDITIONAL portion starts
							// and, I think, also to validate the length of the whole thing.
							$qinfo['ADCOUNT'] += $a2->count();
						}
					    } else {
						//echo "[DEBUG] fwd_lookup says it didn't find anything\n";
					    }
					} //foreach $record
				    } //foreach $recordset
				} // while()

				if( count($a->AU) > 0 ) {
					$answer .= $a->get_data('AU');
					$qinfo['AUCOUNT'] = count($a->AU);	// update AUCOUNT with number of answers
				}

				if( count($a->AD) > 0 ) {
					$answer .= $a->get_data('AD');
					$qinfo['ADCOUNT'] = count($a->AD);	// update AUCOUNT with number of answers
				}

			} // count($a->AN) > 0
		}

		if(! dns_cache_put()) echo "[ERROR] Unable to write dns_cache into shared memory\n";		// after each query write $dns_cache back into shared memory

		shmop_write($ipc['dns-status-map'],str_repeat("\x00",16),($hash_table_offset+$zinfo[2]*16));	// Tell other workers that I have finished resolving.

		//  ----- log entry -----
		if ($settings['logging']) {
			if (isset($a->REVERSE) && $a->REVERSE) {
				$lp = $q->QTYPE.' ('.$q->IP.') -> ';
			} else {
				$lp = $q->QTYPE.' (\''.$q->host.'\') -> ';
			}
			switch($qinfo['REPLYCODE']) {
			case 0: $lp .= $a->get_destination();	break;
			case 1: $lp .= 'Query packet error';	break;
			case 2: $lp .= 'INTERNAL ERROR';	break;
			case 3: $lp .= (($a->REVERSE) ? 'Host':'IP').' not found';	break;
			case 4: $lp .= $q->QTYPE.' not found';	break;
			case 5: $lp .= 'REFUSED'; break;
			}
			log_access($lp = $zinfo[0].' ['.$peer.'] '.$a->src.' '.str_pad(round((microtime(true)-$time)*1000,1),7,' ',STR_PAD_LEFT).' ms (OPCODE='.$qinfo['OPCODE'].',RCODE='.$qinfo['REPLYCODE'].',CLASS='.$q->QCLASS.') '.$lp);
		}
	    }		// for ($qn = 0; $qn < $qinfo['QDCOUNT']; ++$qn)
	}	// if ($qinfo['QR'] == '0')

	$bitmap  = '1'; 				// Query Type (0 - Query, 1 - Response)
	$bitmap .= sprintf('%04b',$qinfo['OPCODE']);	// OP-code (0 - Standart, 1 - Reverse, 2 - Server status query) (4 bits)
	$bitmap .= $qinfo['AA']?'1':'0';		// Authority (1/0)
	$bitmap .= $settings['DNS']['TC']?'1':'0';	// Truncate to 512 bytes
	$bitmap .= $qinfo['RD']?'1':'0';		// Recursive flag
	$bitmap .= $settings['DNS']['RA']?'1':'0';	// Recursive queries enabled? (1/0)
	$bitmap .= '000';				// Zero (3 bits) (reserved for future use)
	$bitmap .= sprintf('%04b',$qinfo['REPLYCODE']);	// Response code (0 - No error, 1 - Query packet error, 2 - Internal server error, 3 - Not found, 4 - Query type is not supported, 5 - Query rejected by server) (4 bits)

	$packet  = _word($qinfo['id']);			// ID
	$packet .= bitmap2bytes($bitmap,2);
	$packet .= _word($qinfo['QDCOUNT']);		// Count of queries in packet
	$packet .= _word($qinfo['ANCOUNT']);		// Count of records included in answer
	$packet .= _word($qinfo['AUCOUNT']);		// Count of source records of authority servers
	$packet .= _word($qinfo['ADCOUNT']);		// Count of records in additional information field
	$packet .= $answer;

/*	// Enable this to see raw response data
	if($settings['DEBUG']) {
	    echo "\n------------------------------- RESPONSE ----------------------------------\n";
	    hex_dump($packet);
	    echo "---------------------------------------------------------------------------\n";
	}
*/
	stream_socket_sendto($bind,$packet,0,$peer);

	shmop_write($ipc['dns-status-map'],"\x00",$zinfo[2]);		// I'm free

	if($settings['DEBUG']) echo '[DEBUG] run_worker() - Time to complete this query: '.round((microtime(true) - $time)*1000,1)." ms\n";

	unset($a); unset($q); unset($qinfo); unset($packet); unset($answer);
	
    }	// while()
}	// function run_worker()

?>
