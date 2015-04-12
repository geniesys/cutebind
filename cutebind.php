<?php
ini_set('display_errors','On');
error_reporting(E_ALL);
define('COREBIND_ROOT',dirname(__FILE__).'/');
define('DNS_CACHE_SIZE', 1024 * 32);					// Size of shared memory used for cache (Bytes) . Default is 32Kb

/*
	Below are minimum default configuration parameters needed to start server without errors.
	Do not change these values here. Use config.php to override it with your user-defined setting.
*/

$settings = array(
	'listen' 	=> '127.0.0.1',					// IP to listen on (IP addr of this host)
	'listen_port' 	=> 53, 						// DNS-server port
	'minDNSworkers' => 10,						// Minimum/Initial number of workers
	'maxDNSworkers' => 20,						// Maximum number of workers
	'pidfile' 	=> COREBIND_ROOT.'cutebind.pid',		// Default pid-file
	'ipcdir' 	=> COREBIND_ROOT.'ipc/', 			// Directory for IPC
	'configfile'	=> COREBIND_ROOT.'config.php',			// Config-file
	'cutebind_path'	=> 'cutebind',					// Path to CuteBind's executable file.
	'accesslog'	=> COREBIND_ROOT.'logs/%DATE=d.m.Y%.log',	// Log storage. This field has special syntax, but it allows simple path.
	'errorlog'	=> COREBIND_ROOT.'logs/error.log',		// Error log storage.
	'cache_dump'	=> COREBIND_ROOT.'logs/cache_dump.txt',		// Cache dump file.
	'intfile'	=> '/tmp/cutebind.intfile.tmp',			// This path must point to file in writable folder (for all CuteBind processes).
	'setuser'	=> '',						// You can set user of master process (sudo).
	'setgroup'	=> '',						// You can set group of master process (sudo).
	'use_fork'	=> TRUE,					// Enables multi-threading if possible.
	'logging'=> array(
			'date_format' => 'Y-m-d H:i:s',			// 'r' for RFC2822 formatted date (Tue, 29 Jul 2014 09:00:09 +0000). See PHP function date() to make your own format.
			'level' => 1					// Logging level (currently is not used)
			),
	'DNS'	=> array(
			'TTL'=> 60,		// Default Time-To-Life (TTL). If DNS record has its own 'ttl', that ttl will be used (regardless of the record source). Otherwise this value.
			'TC' => 0,		// Truncate to 512 bytes
			'RA' => 1,		// Recursive queries enabled? (1/0)
			'RR' => 15		// Use roundrobin for: 1=Inline hash-table, 2=Cached records, 4=Resolver/DB, 8=Lookups, 15=All of the above, 0=none/disabled
			),
	'SBL'	=> array(						// See README.txt
			'hostmatch' => '.sbl.example.tld.',
			'return_ip' => '127.0.0.2',
			'txt'       => 'www.example.com/sbl'
			),
	'DEBUG'		=> FALSE,

	'table'		=> array(					// Simple resolving hash-table (static/permanent/lmhosts).
				'localhost.'	=> array(		// keep it - it acts as cache
							    'A'   => array('127.0.0.1' => array('ttl' => 600)),
							    'AAAA'=> array('::1'       => array('ttl' => 600))
							),
				'127.0.0.1'	=> array(		// keep it - it acts as cache
							    'PTR' => array('localhost' => array('ttl' => 600))
							),
				),
	);

$ver = '2.2';

if (!function_exists('cli_set_process_title')) {function cli_set_process_title($t) {}}

require_once COREBIND_ROOT.'include/common.php';		// Various common functions that are used from this point on.
require_once COREBIND_ROOT.'include/dns-cache.php';		// Everything related to runtime cache feature

$runmode = isset($_SERVER['argv'][1]) ? str_replace('-','',$_SERVER['argv'][1]) : '';
$_SERVER['argv'][1] = '';
$args = getArgs($_SERVER['argv']);
$args_ex = '';

// Load configuration file (in order of priority)
if (isset($args['configfile'])) {				// See if alternative configuration file is specified in the command line.
	$settings['configfile'] = $args['configfile'];		// update $settings['configfile']
	include $settings['configfile'];			// and load it
} elseif( file_exists('config.my.php') ) {			// my personalized configuration
	$settings['configfile'] = 'config.my.php';		// update $settings['configfile']
	include 'config.my.php';				// and load it
} elseif( $settings['configfile'] !== '') {
	include $settings['configfile'];			// Load configuration file specified in $settings['configfile'] (default is config.php)
}

echo "\n";

echo '[INIT] Configuration file: '.$settings['configfile']."\n";

if (!function_exists('resolver')) {				// Test whether function resolver() is defined
	function resolver(&$q,&$a) {return false;}		// If not, define a dummy resolver() that does nothing.
	echo '[INIT] User-defined resolver() function is not declared. Using dummy recolver() which does nothing.'."\n";
} else {
	resolver($null,$null,TRUE);				// Call resolver() to init database connection (No longer necessary since $db is now global)
	echo '[INIT] User-defined resolver() function exists.'."\n";
}


foreach ($args as $k => $v) {					// Iterate command line parameters and update $settings
	$ok = TRUE;
	switch($k) {
	case 'pidfile'	   : $settings[$k] = $v; break;
	case 'listen'	   : $settings['listen'] = $v; break;
	case 'listenport'  : $settings['listen_port'] = $v; break;
	case 'cutebindpath': $settings[$k] = $v; break;
	//case 'configfile'  : $settings[$k] = $v; break;	// already taken care above
	case 'logging'	   : $settings[$k] = (int) $v; break;
	case 'logstorage'  : $settings[$k] = $v; break;
	case 'setuser'     : $settings[$k] = $v; break;
	case 'setgroup'    : $settings[$k] = $v; break;
	case 'intfile'     : $settings[$k] = $v; break;
	case 'debug'	   : $settings['DEBUG'] = true; break;
	default:
		fwrite(STDERR,'[WARN] Unknown parameter \''.$k."'\n");
		$ok = FALSE;
	}
	if ($ok) {$args_ex .= ($args_ex !== ''?' ':'').'--'.$k.'=\''.$v.'\'';}
}

unset($args);	// don't need it anymore

$pidfile = realpath($settings['pidfile']);
if (!file_exists($pidfile)) touch($pidfile);

if ($runmode != 'master') { // We are control script (Command Line Interface)
	// Reason for having it in separate include file is that the master process nor workers
	// ever use any of this code, so they don't need to know about it. Also, makes program
	// easier to read.
	require_once COREBIND_ROOT.'include/cli.php';
	exit(0);
}

// Now, we are the master or the worker (pre-worker). Let's init environment...
cli_set_process_title('cutebind: master process');
$dns_sockets = array();
$zmap        = array();
$ipc         = array();
$ipc_keys    = array();
$ipc_files   = array();
$ipc_prefix  = dechex(crc32($settings['pidfile']));

define('MASTER_PID',getmypid());

if (version_compare(PHP_VERSION,'5.3.0','<')) declare(ticks = 1);

// --- BEGIN --- SHARED MEMORY INITIALIZATION FOR 'dns-status-map' ---------------------------
touch($tp = $settings['ipcdir'].$ipc_prefix.'.dns-status-map.cbt');
$ipc_files[] = $tp;
$ipc_keys['dns-status-map'] = ftok($tp,'t');

if (defined('IS_64b')) $ipc_keys['dns-status-map'] = $ipc_keys['dns-status-map']+($ipc_keys['dns-status-map']/pow(10,strlen($ipc_keys['dns-status-map'])));

@$ipc['dns-status-map'] = shmop_open($ipc_keys['dns-status-map'],'w',0,0);
if ($ipc['dns-status-map']) {
    echo "[INIT] Attached to existing shared memory segment 'dns-status-map'\n";
} else {
    $ipc['dns-status-map'] = shmop_open($ipc_keys['dns-status-map'],'c',0644, $settings['maxDNSworkers']*17);	// block #1 = 1 byte per worker, block #2 = 16 bytes per worker
    if($ipc['dns-status-map']) {
        echo "[INIT] Created new shared memory segment 'dns-status-map' (".($settings['maxDNSworkers']*17)." bytes)\n";
        shmop_write($ipc['dns-status-map'],str_repeat("\x00",$settings['maxDNSworkers']*17),0);			// write a bunch of nulls into this memory segment
    } else {
	log_error("[ERROR] Couldn't create shared memory segment 'dns-q-counter'\n");
	exit(1);
    }
}
// --- END --- SHARED MEMORY INITIALIZATION FOR 'dns-status-map' ---------------------------


// --- BEGIN --- SHARED MEMORY INITIALIZATION FOR 'dns-q-counter' ---------------------------
touch($tp = $settings['ipcdir'].$ipc_prefix.'.dns-q-counter.cbt');
$ipc_files[] = $tp;
$ipc_keys['dns-q-counter'] = ftok($tp,'t');

//if (defined('IS_64b')) $ipc_keys['dns-status-map'] = $ipc_keys['dns-status-map']+($ipc_keys['dns-status-map']/pow(10,strlen($ipc_keys['dns-status-map'])));

@$ipc['dns-q-counter'] = shmop_open($ipc_keys['dns-q-counter'],'w',0,0);
if ($ipc['dns-q-counter']) {
    echo "[INIT] Attached to existing shared memory segment 'dns-q-counter'\n";
} else {
    $ipc['dns-q-counter'] = shmop_open($ipc_keys['dns-q-counter'],'c',0644,$settings['maxDNSworkers']*4);	// 4 bytes (dword) per worker
    if($ipc['dns-q-counter']) {
        echo "[INIT] Created new shared memory segment 'dns-q-counter' (".($settings['maxDNSworkers']*4)." bytes)\n";
    } else {
	log_error("[ERROR] Couldn't create shared memory segment 'dns-q-counter'\n");
	exit(1);
    }
}
shmop_write($ipc['dns-q-counter'],str_repeat("\x00",$settings['maxDNSworkers']*4),0);				// write a bunch of nulls into this memory segment
// --- END --- SHARED MEMORY INITIALIZATION FOR 'dns-q-counter' ---------------------------


// --- BEGIN --- SHARED MEMORY INITIALIZATION FOR 'dns-cache' ---------------------------
touch($tp = $settings['ipcdir'].$ipc_prefix.'.dns-cache.cbt');
$ipc_files[] = $tp;
$ipc_keys['dns-cache'] = ftok($tp,'t');

@$ipc['dns-cache'] = shmop_open($ipc_keys['dns-cache'],'w',0,0);
if ($ipc['dns-cache']) {
    echo "[INIT] Attached to existing shared memory segment 'dns-cache'\n";
    if( shmop_size($ipc['dns-cache']) != DNS_CACHE_SIZE ) {
	//if($settings['DEBUG'])
	echo '[DEBUG] Size of shared memory allocated to cache ('.(shmop_size($ipc['dns-cache'])/1024).' Kb) does not match DNS_CACHE_SIZE constant ('.(DNS_CACHE_SIZE/1024)." Kb) - attempting to recreate.\n";
	if(shmop_delete($ipc['dns-cache'])) {
		echo "[DEBUG] shared memory block is deleted\n";
		if(shmop_close ($ipc['dns-cache'])) {
			echo "[DEBUG] shared memory segment is closed\n";
		} else {
			echo "[DEBUG] shared memory segment is NOT closed\n";
		}
	} else {
		echo "[DEBUG] shared memory block is NOT deleted\n";
	}
	// Recreate shared memory block with proper size
	$ipc['dns-cache'] = shmop_open($ipc_keys['dns-cache'],'c',0644,DNS_CACHE_SIZE);
	if($ipc['dns-cache']) {
	    echo "[DEBUG] Created new shared memory segment 'dns-cache' (".DNS_CACHE_SIZE." bytes)\n";
	} else {
	    log_error("[ERROR] Couldn\'t create shared memory segment 'dns-cache'\n");
	    exit(1);
	}
	if( shmop_size($ipc['dns-cache']) != DNS_CACHE_SIZE ) {
		echo '[ERROR] Size of shared memory allocated to cache ('.(shmop_size($ipc['dns-cache'])/1024).' Kb) does not match DNS_CACHE_SIZE constant ('.(DNS_CACHE_SIZE/1024)." Kb).\n";
		exit(1);
	}
    }
} else {
    $ipc['dns-cache'] = shmop_open($ipc_keys['dns-cache'],'c',0644,DNS_CACHE_SIZE);
    if($ipc['dns-cache']) {
	echo "[INIT] Created new shared memory segment 'dns-cache' (".DNS_CACHE_SIZE." bytes)\n";
    } else {
	log_error("[ERROR] Couldn't create shared memory segment 'dns-cache'\n");
	exit(1);
    }
}

$s = rtrim(shmop_read($ipc['dns-cache'],0,DNS_CACHE_SIZE));
$i = strlen($s);
if( $i ) {
    // Check shared memory. If not empty, load it into $dns_cache object overwriting default values.
    echo str_pad('[INIT] Loading dns-cache from shared memory',55,'.');
    echo ((dns_cache_get()) ? 'OK' : 'FAILED')."\n";
    //if($dns_cache['DEBUG']) print_r($dns_cache);
} else {
    // write our initial $dns_cache object into this memory. No need to write a bunch of nulls because dns_cache_put() pads json string with nulls.
    echo str_pad('[INIT] Initializing dns-cache using template',55,'.');
    //$dns_cache['DIRTY'] = TRUE;						// Set to TRUE to force write into shared memory
    echo ((dns_cache_put()) ? 'OK' : 'FAILED')."\n";
}
unset($s);
// --- END --- SHARED MEMORY INITIALIZATION FOR 'dns-cache' ---------------------------

// Init database connection (this is going to be single connection shared by all workers)
if(isset($settings['mysql']['host'])) {
    echo str_pad('[INIT] Connecting to MySQL server '.$settings['mysql']['host'],55,'.');
    $db = connect_db();
    if($db) {
	echo "OK\n";
    } else {
	echo "FAILED\n";
	echo mysqli_connect_error()."\n";
	echo "[WARN] All functions that require database access will not be available.\n";
    }
}

echo "[STATUS] Cache: ".((int)DNS_CACHE_SIZE/1024).' KB; '.count($dns_cache['table']).' hosts, '.$i.' bytes, '.round($i*100/DNS_CACHE_SIZE,2).'% usage; TTL '.$dns_cache['TTL']." sec.\n";

require_once COREBIND_ROOT.'include/worker.php';

if ($runmode == 'master') {
    // We are the master. Include module that has additional functionality that only master process uses.
    require_once COREBIND_ROOT.'include/master.php';
}
?>
