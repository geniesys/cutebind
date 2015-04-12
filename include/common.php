<?php		// Library of functions

function connect_db() {
	global $db, $settings;

	if( $db && @mysqli_ping($db) ) return $db;		// already connected. Quit immediately.

	if( !empty($settings['mysql']) ) {
		$p = &$settings['mysql'];
		//@ $db = mysqli_connect($p['host'].(isset($p['port'])?':'.$p['port']:''), $p['user'], isset($p['pass'])?$p['pass']:'', trim($p['path'],'/'));		// regular connection (closed when the script ends)
		//@ $db = mysqli_connect(     $p['host'], $p['user'], $p['pass'], $p['base'], ($p['port']=='') ? NULL : $p['port']);	// regular connection (closed in few minutes of inactivity)
		@ $db = mysqli_connect('p:'.$p['host'], $p['user'], $p['pass'], $p['base'], ($p['port']=='') ? NULL : $p['port']);	// persistent connection (closed when program ends)
		return $db;
	}

	return NULL;
}

function log_access($log,$reopen = FALSE) {
	global $settings;
	static $p;
	if (($p === NULL) || $reopen) {
		if($p !== NULL) fclose($p);
		$p = fopen(parse_storagepath($settings['accesslog']),'a');
	}
	if ($log !== '') {
		$log = '['.date($settings['logging']['date_format']).'] '.$log;
		fwrite($p,$log."\n");
		echo $log."\n";
	}
}

function log_error($log,$reopen = FALSE) {
	global $settings;
	static $p;
	if (($p === NULL) || $reopen) {
		if($p !== NULL) fclose($p);
		$p = fopen(parse_storagepath($settings['errorlog']),'a');
	}
	if ($log !== '') {
		$log = '['.date($settings['logging']['date_format']).'] '.$log;
		fwrite($p,$log."\n");
		echo $log."\n";
	}
}

function parse_storagepath_callback1($m) {
	$e = explode('=',$m[1]);
	if ($e[0] == 'DATE') {return date($e[1]);}
	return $m[0];
}

function parse_storagepath($path) {
	$path = preg_replace_callback('~%(.*?)%~','parse_storagepath_callback1',$path);
	if (stripos($path,'file://') === 0) {$path = substr($path,7);}
	return $path;
}

function is_assoc($a) {
	$a = array_keys($a);
	return ($a !== array_keys($a));
}

function getArgs($args) {
	$out = array();
	$last_arg = null;
	for($i = 1, $il = sizeof($args); $i < $il; $i++) {
		if( (bool)preg_match("/^--(.+)/", $args[$i], $match) ) {
			$parts = explode("=", $match[1]);
			$key = preg_replace("/[^a-z0-9]+/", "", $parts[0]);
			if(isset($parts[1])) {
				$out[$key] = $parts[1];   
			} else {
				$out[$key] = true;   
			}
			$last_arg = $key;
		} elseif( (bool)preg_match("/^-([a-zA-Z0-9]+)/", $args[$i], $match) ) {
			for( $j = 0, $jl = strlen($match[1]); $j < $jl; $j++ ) {
				$key = $match[1]{$j};
				$out[$key] = true;
			}
			$last_arg = $key;
		} elseif($last_arg !== null) {
			$out[$last_arg] = $args[$i];
		}
	}
	return $out;
}

// Functions used for debugging.

function hex_dump($data, $newline="\n") {
	static $from  = '';
	static $to    = '';
	static $width = 16;	// number of bytes per line
	static $pad   = '.';	// padding for non-visible characters

	if ($from==='') {
		for ($i=0; $i<=0xFF; $i++) {
			$from .= chr($i);
			$to .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
		}
	}

	$hex   = str_split(bin2hex($data), $width*2);
	$chars = str_split(strtr($data, $from, $to), $width);

	$offset = 0;
	foreach ($hex as $i => $line) {
		echo sprintf('%6X',$offset) . str_pad(' : ' . implode(' ', str_split($line,2)),50) . ' [' . str_pad($chars[$i],16) . ']' . $newline;
		$offset += $width;
	}
}

function hecho($string) {
	return preg_replace('~.~se','sprintf("\\x%02x",ord("$0"))',$string);
}

?>