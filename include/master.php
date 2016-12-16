<?php
// This code is available only to master process. Workers don't have to know anything about this.
$e = explode(',',$settings['listen']);

for ($i = 0, $s = sizeof($e); $i < $s; ++$i) {
	$ih = explode(':',$e[$i]);
	if (!isset($ih[1])) $ih[1] = $settings['listen_port'];
	($bind = stream_socket_server('udp://'.$ih[0].':'.$ih[1],$errno,$errstr,STREAM_SERVER_BIND)) || exit(0);
	//if (!socket_set_option($bind,SOL_SOCKET,SO_REUSEADDR,1)) {exit(socket_strerror(socket_last_error($bind)));}
	$dns_sockets[] = $bind;
}

if (isset($settings['setgroup']) && ($settings['setgroup'] !== '')) {
    if (($sg = posix_getgrnam($settings['setgroup'])) === FALSE) {
	log_access('[ERROR] Couldn\'t change group to \''.$settings['setgroup'].'\'. You must replace config-variable \'setuser\' with existing username.');
	exit(0);
    } elseif (($sg != getmygid()) && (!posix_setgid($sg['gid']))) {
	log_access('[ERROR] Couldn\'t change group to \''.$settings['setgroup']."'. Error (".posix_get_last_error().'): '.posix_strerror(posix_get_last_error()));
	exit(0);
    }
}

if (isset($settings['setuser']) && ($settings['setuser'] !== '')) {
      if (($su = posix_getpwnam($settings['setuser'])) === FALSE) {
	  log_error('[ERROR] Couldn\'t change user to \''.$settings['setuser'].'\', user not found. You must replace config-variable \'setuser\' with existing username.');
	  exit(0);
      } elseif (($su != getmyuid()) && (!posix_setuid($su['uid']))) {
	  log_error('[ERROR] Couldn\'t change user to \''.$settings['setuser']."'. Error (".posix_get_last_error().'): '.posix_strerror(posix_get_last_error()));
	  exit(0);
      }
}

if (!sizeof($dns_sockets)) {
      $msg = "[ERROR] No listening ports for DNS server.\n";
      fwrite($plog,$msg);
      echo $msg;
      exit(0);
}

for ($i = 0; $i < $settings['minDNSworkers']; ++$i) run_worker('dns');

echo "[STATUS] CuteBind $ver. System is up. Debugger: ".(($settings['DEBUG']) ? 'ON':'OFF').". Master PID: ".getmypid().". Accepting connections on ".$settings['listen'].':'.$settings['listen_port'].".\n\n";

define('START_TIME',time());

function master_sighandler($signo) {

	global $settings;
	global $zmap;
	global $ipc_files;
	global $ipc;
	global $dns_cache;

	static $signals = array(
		SIGHUP  => 'SIGHUP (1)  Debugger ON/OFF',	// (Ping-pong)
		SIGINT  => 'SIGINT (2)',			// catches Ctrl+C
		SIGQUIT => 'SIGQUIT (3)',
		SIGABRT => 'SIGABRT (6)',
		SIGKILL => 'SIGKILL (9)',
		SIGUSR1 => 'SIGUSR1 (10) Fullstatus',
		SIGUSR2 => 'SIGUSR2 (12) Reopen/rotate logs',
		SIGTERM => 'SIGTERM (15)'
	);

	echo '[STATUS] Master caught signal '.$signals[$signo].".\n";
	switch($signo) {
	case SIGHUP:			// Debugger ON/OFF
		$settings['DEBUG'] = !$settings['DEBUG'];
		echo 'Debugger is '.(($settings['DEBUG']) ? 'ON':'OFF')."\n";
		foreach ($zmap['dns'] as $v) {
			posix_kill($v[0],SIGHUP);
		}

		$fp = fopen($settings['cache_dump'],'w');
		fwrite($fp,var_export($dns_cache,true));
		fclose($fp);
		echo 'DNS Cache content is written into '.$settings['cache_dump']."\n";
		break;

	case SIGUSR1:			// fullstatus-report
		$v  = time()-START_TIME;
		$q_counter = get_q_counter('dns');
		$status = 'Uptime: '.date_period_text(START_TIME,time())."\n";
		$status .= 'Concurency DNS-queries: '.get_concurency('dns')."\n";
		$status .= 'Total queries: '.$q_counter."\n";
		$status .= 'Queries per second (avg): '.($q_counter/$v)."\n";
		$status .= 'real_mem='.memory_get_usage(TRUE)."\n";
		$status .= 'emalloc_mem='.memory_get_usage(FALSE)."\n";
		$i = 0;
		foreach (getrusage() as $k => $v) {$status .= $k.'='.$v.((++$i%2 == 0)?"\n":"\t\t\t\t");}

		dns_cache_get();
		$i = strlen(rtrim(shmop_read($ipc['dns-cache'],0,DNS_CACHE_SIZE)));
		$status .= "\nCache: ".((int)DNS_CACHE_SIZE/1024).' KB; '.count($dns_cache['table']).' hosts, '.$i.' bytes, '.round($i*100/DNS_CACHE_SIZE,2).'% usage; TTL '.$dns_cache['TTL']." sec.\n";

		$fp = fopen($settings['tmpfile'].'.new','w');
		fwrite($fp,$status);
		fclose($fp);
		rename($settings['tmpfile'].'.new',$settings['tmpfile']);
		echo $status;
		break;

	case SIGUSR2:			// reopen logs
		reopen_logstorages();
		break;

	default:
	    if( $signo = SIGINT || $signo == SIGQUIT || $signo == SIGABRT || $signo == SIGKILL || $signo == SIGTERM ) {
		$status = 0;
		if(!defined('TERMINATED')) define('TERMINATED',TRUE);		// Occasionaly get PHP Notice: Constant TERMINATED already defined in /usr/local/cutebind/cutebind on line ...
		echo '[STATUS] Sending SIGTERM to all workers.'."\n";
		foreach ($zmap['dns'] as $v) {
			posix_kill($v[0],SIGTERM);
			pcntl_waitpid($v[0],$status);		// book says should call pcntl_wait() or pcntl_waitpid(). It works faster without it, but may produce zombies. Syntax: pcntl_wait(int $status[, int options = 0]); Returns: pid (ok) | -1 (err) | 0 (no child/already exited)
//			usleep(100000);				// wait 0.1 sec so that workers don't start closing resources all at the same time
		}
		sleep(1);					// wait 1 more sec before closing all resources to let worker(s) finish current response (if any).
		foreach ($ipc_files as $v) {
			echo $v."\n";
			@unlink($v);
		}

		// release shared memory on exit.
		shmop_delete($ipc['dns-status-map']);		// delete goes before close
		shmop_delete($ipc['dns-q-counter']);
		shmop_delete($ipc['dns-cache']);
		shmop_close ($ipc['dns-status-map']);
		shmop_close ($ipc['dns-q-counter']);
		shmop_close ($ipc['dns-cache']);

		exit(0);
	    }
	}
}

pcntl_signal(SIGTERM,'master_sighandler');
pcntl_signal(SIGABRT,'master_sighandler');
pcntl_signal(SIGQUIT,'master_sighandler');
pcntl_signal(SIGINT ,'master_sighandler');
pcntl_signal(SIGHUP ,'master_sighandler');
pcntl_signal(SIGUSR1,'master_sighandler');
pcntl_signal(SIGUSR2,'master_sighandler');

$fp = fopen($settings['pidfile'],'w');
fwrite($fp,getmypid());
fclose($fp);

$schedule = array(
		'check_logstorages' => 10,
		'check_loadbalance' => 5,
		'cache_DTA'         => 5,
	);

$schedule_last = array();

while (TRUE) {
	sleep(5);
	for ($i = 0, $k = array_keys($schedule), $s = sizeof($schedule); $i < $s; ++$i)
	{
		if (!isset($schedule_last[$k[$i]])) $schedule_last[$k[$i]] = 0;
		if ($schedule_last[$k[$i]] < time()-$schedule[$k[$i]]) {
			$schedule_last[$k[$i]] = time();
			call_user_func($k[$i],$schedule[$k[$i]]);
		}
	}
}

function get_concurency($t) {
	global $settings;
	global $ipc;
	global $zmap;
	$tmp = shmop_read($ipc[$t.'-status-map'],0, $settings['maxDNSworkers']);
	//echo "[DEBUG] ------ dns-status-map -----\n";
	//hex_dump($tmp);
	//echo "[DEBUG] ------ zmap -----\n";
	//print_r($zmap);
	$c = 0;
	foreach ($zmap[$t] as $v) {
		if(substr($tmp,$v[2],1) == "\x01") ++$c;
	}
	return $c;
}

function get_q_counter($t) {
	global $settings;
	global $ipc;
	global $zmap;
	$tmp = shmop_read($ipc[$t.'-q-counter'],0,$settings['maxDNSworkers']*4);
	//echo "[DEBUG] ------ dns-q-counter ------\n";
	//var_dump($tmp);
	$c = 0;
	foreach ($zmap[$t] as $v) {
	    $x = substr($tmp,$v[2]*4,4);	// Assigning to a variable prevents warning "PHP Strict Standards: Only variables should be passed by reference in ..."
	    $c += _get_dword($x);		// that occurs here.
	}
	return $c;
}

function reopen_logstorages() {
	global $zmap;
	log_access('',TRUE);
	log_error ('',TRUE);
	echo '[STATUS] reopen_logstorages() - Master process '.getmypid().' is sending SIGUSR2 to all workers.'."\n";
	foreach ($zmap['dns'] as $v) {posix_kill($v[0],SIGUSR2);}
}

function check_logstorages($interval) {
	global $settings;
	static $l;
	$a = array(
		'access' => parse_storagepath($settings['accesslog']),
		'error'  => parse_storagepath($settings['errorlog'])
		);
	$k = array_keys($a);
	if ($l === NULL) {$l = $a; return;}
	for ($i = 0,$s = sizeof($l); $i < $s; ++$i) {
		if ($a[$k[$i]] != $l[$k[$i]]) {
			$l = $a;
			reopen_logstorages();
			break;
		}
	}
}

function check_loadbalance($interval) {
	global $settings;
	global $zmap;		// worker processes collection
	global $ipc_files;
	static $counter = 0;

	if ($counter < 0) $counter = 0;

	if (get_concurency('dns') == count($zmap['dns'])) ++$counter; else --$counter;

	if ($counter >= (20/$interval)) {
	    if (count($zmap['dns'])+1 >= $settings['maxDNSworkers']) {
		log_error('[LOAD-BALANCER] It looks like you should increase \'maxDNSworkers\' variable.');
	    } else {
		if($settings['DEBUG']) echo '[LOAD-BALANCER] check_loadbalance() - Starting new worker process.'."\n";
		run_worker('dns');
	    }
	    --$counter;
	} else {
	    if (count($zmap['dns']) > $settings['minDNSworkers']) {
		//echo '$zmap[dns] = '; print_r($zmap['dns']);
		//echo 'First worker pid = '.$zmap['dns'][0][0]."\n";
		//echo 'Last  worker pid = '.$zmap['dns'][count($zmap['dns'])-1][0]."\n";
		//echo 'count(count($zmap[dns])) = '.count($zmap['dns'])."\n";
		//$_pid  = $zmap['dns'][count($zmap['dns'])-1][0];
		$_pid   = end($zmap['dns'])[0];
		$status = 0;
		if($settings['DEBUG']) echo '[LOAD-BALANCER] check_loadbalance() - Shuting down worker (pid:'.$_pid.")\n";
		if(posix_kill($_pid,SIGTERM) && pcntl_wait($status) > -1) {	//A.D. book says should call pcntl_wait(). It can work without it too, though. Syntax: pcntl_wait(int $status[, int options = 0]); Returns: pid (ok) | -1 (err) | 0 (no child/already exited)
			//if($settings['DEBUG']) echo "OK (status $status)\n";
			unset( $zmap['dns'][key($zmap['dns'])]);
		} else {
			//if($settings['DEBUG']) echo "FAILED (status $status)\n";
		}
	    }
	}
}

?>