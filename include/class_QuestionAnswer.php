<?php
/*
	Question and Answer classes.
	Question object is used to pass DNS query Question (as data stucture) to one of the resolvers. Question object
	can also parse "question" portion of binary DNS packet (less headers) to initialize its own properties.
	Answer object is used to pass the result of a lookup from resolvers back to parent. Answer may contain zero, one
	or more	DNS records in form of an associative array. Answer object can also convert this array to a binary string
	suitable to be part of the response packet.
*/

class _base_QuestionAnswer {		// Common parts of Question and Answer classes. Don't use this class directly.
	public $QTYPE;
	public $QTYPE_INT;
	public $QCLASS	   = 'IN';
	public $QCLASS_INT = 1;

	public function set_type($str_or_int) {
		global $QTYPES;

		if( isset($QTYPES[$str_or_int]) ) {
		    if(is_numeric($str_or_int)) {
			$this->QTYPE_INT = $str_or_int;
			$this->QTYPE     = $QTYPES[$str_or_int];
		    } elseif(is_string($str_or_int)) {
			$this->QTYPE_INT = $QTYPES[$str_or_int];
			$this->QTYPE     = $str_or_int;
		    } else {
			log_error('[ERROR] Object _base_QuestionAnswer:set_type() - Invalid argument type. String or Int is expected.');
		    }
		} else {
			$this->QTYPE_INT = 0;
			$this->QTYPE     = 'UNK '.$str_or_int;
		}
	}

	public function set_class($str_or_int) {
		global $QCLASSES;

		if( isset($QCLASSES[$str_or_int]) ) {
		    if(is_numeric($str_or_int)) {
			$this->QCLASS_INT = $str_or_int;
			$this->QCLASS     = $QCLASSES[$str_or_int];
		    } elseif(is_string($str_or_int)) {
			$this->QCLASS_INT = $QCLASSES[$str_or_int];
			$this->QCLASS     = $str_or_int;
		    } else {
			log_error('[ERROR] Object _base_QuestionAnswer:set_class() - Invalid argument type. String or Int is expected.');
		    }
		} else {
			$this->QCLASS_INT = 0;
			$this->QCLASS     = 'UNK '.$str_or_int;
		}
	}
}

class Question extends _base_QuestionAnswer {
/*
Question Object
(
    [host] => twitter.com.
    [l_host] => twitter.com.
    [bin_host] => twittercom
    [IP] => Array()
    [QTYPE_INT] => 1
    [QCLASS_INT] => 1
    [QTYPE] => A
    [QCLASS] => IN
)
*/
	public $host;
	public $l_host;
	public $bin_host;
	public $IP;
	public $peer_ip;		// Currently used in GeoIP resolver() only. May want to pass it there somehow else and remove from here (?)
	public $peer_port;		// Currently used in GeoIP resolver() only. May want to pass it there somehow else and remove from here (?)

	public function Question( &$data = null, $peer = null) {	// initialization function called automatically.
		// You can pass $data and $peer parameters to have this object initialize itself in one step.
		// Otherwise, call set_data($data) and set_peer($peer) separately right after creating your object.
		if(! is_null($data) )	$this->set_data($data);
		if(! is_null($peer) )	$this->set_peer($peer);		// used in GeoIP resolver() only
	}

	public function set_data(&$data) {
		for (;;) {
			$l = ord($data[0]);
			$p = substr($data,1,$l);
			$this->host     .= $p.(($l !== 0) ? '.' : '');
			$this->bin_host .= $data[0].$p;
			$data = substr($data,$l+1);
			if ($l === 0) break;
		}
		$this->l_host     = strtolower($this->host);
		$this->set_type (_get_word($data));
		$this->set_class(_get_word($data));
	}

	public function set_peer($peer) {	// Currently needed by GeoIP resolver() only. May want to pass it there somehow else and remove from here (?)
		$e = explode(':',$peer);
		$this->peer_ip   = $e[0];
		$this->peer_port = $e[1];
	}
}

class Answer extends _base_QuestionAnswer {
/*
Answer Object
(
    [host] => 
    [l_host] => 
    [bin_host] => 
    [REVERSE] => 
    [HAS_TARGETS] => 
    //[R_DOMAIN] => 
    //[RDATA] => Array()
    [AN] =>
    [AU] =>
    [AD] =>
    [src] => '?'
    [dest] => ''
    [QTYPE_INT] => 1
    [QCLASS_INT] => 1
    [QTYPE] => A
    [QCLASS] => IN
)
*/
	public $host;
	public $l_host;
	public $REVERSE;
	public $HAS_TARGETS;
	//public $R_DOMAIN;
	//public $RDATA = array();
	public $AN = array();
	public $AU = array();
	public $AD = array();
	public $src;		// One character code to indicate where answer was obtained from (? - Unknown, T - Static table, C - cache, R - resolver(), L - lookup)
	public $dest;		// Human-readable "destination" (list of IP addresses or hosts) for log messages.
	private $q;		// Pointer to the original Question object

	public function Answer(&$q) {	// initialization function called automatically
		// $q is reference to original Question object. We need to get some values from there.
		$this->src         = '?';
		$this->dest        = '';
		$this->REVERSE     = false;
		$this->HAS_TARGETS = false;

		// Unless we say otherwise, assume that 'type' and 'class' of the Answer is the same as Question
		$this->QTYPE_INT   = $q->QTYPE_INT;
		$this->QCLASS_INT  = $q->QCLASS_INT;
		$this->QTYPE       = $q->QTYPE;
		$this->QCLASS      = $q->QCLASS;
		
		// Unless we say otherwise, assume 'host' is the same as in Question
		$this->host        = $q->host;
		$this->l_host      = $q->l_host;

		// Remember pointer to the original Question object
		$this->q = &$q;
	}

	public function count() {		// Returns number of ANSWERs.
		// If answer came from cache, make sure you did not include record expiration timestamp (index [0]) into RDATA.
		// It is not a DNS record. If you did, then you need to unset($abc[0]) right after you copied cached records into RDATA.
		$i = 0;
		//foreach( $this->RDATA as $recordset ) {
		//    $i += count($recordset);
		//}
		foreach( $this->AN as $recordset ) {
		    $i += count($recordset);
		}
		foreach( $this->AU as $recordset ) {
		    $i += count($recordset);
		}
		foreach( $this->AD as $recordset ) {
		    $i += count($recordset);
		}
		return $i;
	}
	
	public function get_data($collection = null) {
		/*	Walks through AN(swer),AU(thority), and AD(ditional) collections, collection of records (by type) whithin these collections,
			and resource records itself. Converts resource records to its binary form according to its type. Puts together all
			these binary pieces (individual answers) into one piece - the ANSWER portion of the server response. 
			Note that it is quite common to return multiple ANSWERs for single QUESTION. Think of a host having multiple IP's.
			If this function finds that $AN contains more than one record, it will return all of them as multiple ANSWERs.
			Also note that server response may includes additional ANSWER records caused by subsequent recursive lookups as
			well as AUTHORITY and/or ADDITIONAL record(s) that follow primary ANSWER(s). Worker handles these recursive lookups.
		*/
		global $settings;
		global $QTYPES;

		$answer = '';

		if($collection == null) {
			$collections = array($this->AN,$this->AU,$this->AD);
		} else {
			$collections = array($this->$collection);
		}

		foreach( $collections as $collection) {
		    foreach( $collection as $type => $recordset ) {
			if($type == '0') continue;					// Never mind. This is record expiration timestamp.
			//echo 'Answer->get_data():193 - Looking at set of records of type '.$type."\n";
			if( count($recordset)==0 ) continue;				// Recordset has no data - either a special record that indicates host/ip wasn't found or some sort of problem. In either case we cannot continue and must move to the next record.
			foreach( $recordset as $key => $record ) {
				//echo 'Answer->get_data():196 - Looking at '.$type.' record for '.$key."\n";

				// Nothe that array $record is used only once per itteration. We don't need to remember it beyond this switch().
				// We will override it with a binary string produced as the result of the conversion (destroying original array).
				switch($type) {
				case 'A':
					$record = _dword(ip2long($key));		// convert IPv4 to its binary form
					break;
				case 'NS':
					$this->HAS_TARGETS = true;			// This record contains name of a host that needs to be recursively looked up for its IP's
					$record = _labels($key);
					break;
				case 'CNAME':
					$this->HAS_TARGETS = true;			// This record contains name of a host that needs to be recursively looked up for its IP's
					$record = _labels($key);
					break;
				case 'PTR':
					$record = _labels($key.'.');			// convert host/domain to its binary form
					break;
				case 'AAAA':
					$record = inet_pton($key);			// convert IPv6 to its binary form
					break;
				case 'MX':
					$this->HAS_TARGETS = true;			// This record contains name of a host that needs to be recursively looked up for its IP's
					$record = _word($record['pri']).
						  _labels($key);			// convert and format MX to its binary form
					break;
				case 'SOA':						// Note: There is only one SOA allowed per domain, but we don't check for this.
					$this->HAS_TARGETS = true;			// This record contains name of a host that needs to be recursively looked up for its IP's
					$record = _labels($key).
						  _labels($record['rname']).
						  _dword ($record['serial']).
						  _dword ($record['refresh']).
						  _dword ($record['retry']).
						  _dword ($record['expire']).
						  _dword ($record['minimum-ttl']);	// convert and format SOA to its binary form
					break;
				case 'SRV':
					$record = _word($record['pri']).
						  _word($record['weight']).
						  _word($record['port']).
						  _labels($key);			// convert and format SRV to its binary form
					break;
				case 'HINFO':
					$record = chr(strlen($record['cpu'])).
						  $record['cpu'].
						  chr(strlen($record['os'])).
						  $record['os'];			// convert and format HINFO to its binary form
					break;
				case 'TXT':
					$record = chr(strlen($record['txt'])).
						  $record['txt'];			// convert and format TXT to its binary form
					break;
				default:
					echo '[!] Query of type '.$this->QTYPE." is not supported.\n";
					continue;
				}

				// DNS Packet Compression
				// When host in Answer is the same as in Question DNS standard allows use of a pointer to the original
				// name instead of repeating that name in the answer. "\xc0\x0c" is the pointer that does the trick. 
				//if($this->l_host != $this->q->l_host) {
				if( in_array( $this->QTYPE, array('A','AAAA') ) ) {
					$answer .= _labels($this->host);	//p1
				} else {
					$answer .= "\xc0\x0c";			//p1
				}
				$answer .= _word($QTYPES[$type]);		//p1-1
				$answer .= _word($this->QCLASS_INT);		//p1-2
				$answer .= _dword( isset($record['ttl']) ? $record['ttl'] : $settings['DNS']['TTL'] );	// if possible, use TTL received from parent DNS server. Otherwise use default TTL.
				$answer .= _word(strlen($record));
				$answer .= $record;

			} // foreach $record
		    } // foreach $recordset
		} // foreach $collection

/*		
		if( in_array( $this->QTYPE, array('CNAME','NS','MX','SOA') ) ) {
			$this->HAS_TARGETS = true;	// Record of these types contain hostname that needs to be recursively looked up for its IP's
		}
*/
		return $answer;
	}

	public function get_destination() {	// The following builds human-readable "destination" part of the log entry. Format varies according to record type.

		if(count($this->AN)==0) {
			log_error('[ERROR] Answer:get_destination() - Cannot build destination string. Answer contains no records. Review your code. You shouldn\'t even call this method in such case. Set or handle return code 3 so that you don\'t even get here.');
			return;
		}

		foreach(array($this->AN,$this->AU,$this->AD) as $collection) {
		  foreach( $collection as $type => $recordset ) {
		    if($type == '0') continue;				// Never mind. This is record expiration timestamp.
		    if( in_array($type,array('A','CNAME','PTR','NS','AAAA')) ) {
			$a[] = $type.' ('.implode(',',array_keys($recordset)).')';
		    } elseif( count($recordset) ) {
			foreach( $recordset as $key => $record ) {
				switch($type) {
				case 'MX' :	$b[] = $record['pri'].'='.$key; break;
				case 'SRV':	$b[] = $record['pri'].'='.$key.':'.$record['port'].','.$record['weight']; break;
				case 'TXT':	$b[] = substr($record['txt'],0,23).'..'; break;
				case 'SOA':	$b[] = $record['serial'].'='.$key.','.$record['rname'];	break;
				case 'HINFO':	$b[] = 'cpu='.$record['cpu'].', os='.$record['os'];	break;
				default:
				      unset($record['ttl']);
				      $b[] = $key.'=['.implode(',',$record).']';
				}
			}
			$a[] = $type.' ('.implode(';',$b).')';
			unset($b);
		    }
		  }
		}
		return implode(', ', $a) ;
	}
}

?>