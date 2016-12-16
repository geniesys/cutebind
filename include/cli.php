<?php

    $_pid = (float) file_get_contents($settings['pidfile']);
    $startcmd = ($cmd = $settings['cutebind_path'].' master '.rtrim($args_ex)).' >> cutebind.out &';

    switch(strtolower($runmode)) {
    case 'debug':
	echo '[STATUS] CuteBind is '.(($_pid and posix_kill($_pid,SIGHUP)) ? '':'NOT ').'running ('.$settings['pidfile'].").\n";
	break;

    case 'status':
	if (! $_pid) {
	    echo "[DEBUG] CuteBind process id is unknown. ".$settings['pidfile']." file not found.\n";
	    break;
	}

	if (! posix_kill($_pid,SIGHUP)) {
	    echo "[STATUS] CuteBind is not running.\n";
	    break;
	}

	if (file_exists($settings['tmpfile'])) unlink($settings['tmpfile']);		// delete previous report, if found.

	if (posix_kill($_pid,SIGUSR1)) {
		echo 'Fetching status... ';
		usleep(500000);								// give it half a second to create new report
		$ok = FALSE;
		for($i = 0; $i < 30; $i++) {
		    if(file_exists($settings['tmpfile'])) $ok = TRUE; break;
		    usleep(500000);
		}
		if ($ok) {
		    echo "OK.\n".file_get_contents($settings['tmpfile'])."\n\n";
		    unlink($settings['tmpfile']);					// delete report after is has been displayed.
		} else {
		    echo "FAILED.\n\n";
		    echo 'File '.$settings['tmpfile']." does not exist or access denied. Permissions?\n";
		}
		echo 'Content of dns cache is dumped into '.$settings['cache_dump']."\n";
	} else {
		echo "\n[DEBUG] Sending SIGUSR1 to $_pid failed.\n";
	}
	break;

    case 'start':
	if ($_pid && posix_kill($_pid,SIGHUP)) {
	    echo 'ERROR. CuteBind with pid-file \''.$settings['pidfile'].'\' is running alredy (PID '.$_pid.")\n";
	} else {
	    shell_exec($startcmd);
	    $i = 0;
	    $ok = TRUE;
	    while (TRUE) {
	      if (file_exists($settings['pidfile']) && ($_pid = file_get_contents($settings['pidfile'])) && posix_kill($_pid,SIGHUP)) {
		$ok = TRUE;
		break;
	      }
	      $ok = FALSE;
	      usleep(500000);
	      if ($i > 10) break;
	      ++$i;
	    }
	    if (!$ok) {echo "[START] Starting... ERROR. Process hasn't daemonized (PID - ".($_pid?$_pid:'UNKNOWN')."). Try to run the following command manually and fix an error:\n".$cmd."\n";}
	}
	break;

    case 'restart':
	echo '[RESTART] Sending SIGTERM to '.$_pid.'... '.(($ok = ($_pid && posix_kill($_pid,SIGTERM))) ? 'OK.' : 'ERROR. It seems that CuteBind is not responding.')."\n";
	if ($ok) {
	    $i = 0;
	    while ($r = $running = posix_kill($_pid,SIGHUP)) {
		usleep(500000);
		if ($i == 9) {
			echo ' CuteBind master-process hasn\'t finish. Sending SIGKILL... '.(($ok = ($_pid && posix_kill($_pid,SIGKILL))) ? 'OK.':'ERROR. Permissions?')."\n";
			if ($ok) {
			    if (!posix_kill($_pid,SIGHUP)) {
				$running = FALSE;
				echo " Oh, his blood is on my hands :'(\n";
			    } else {
				$running = TRUE;
				echo "ERROR: Process alive. Permissions?\n";
			    }
			}
			break;
		}
		++$i;
	    }
	    if (!$r) echo "\n";
	} else {
		$running = FALSE;
	}
 
	if (!$running) {
		echo "[START] Starting CuteBind... ";
		shell_exec($startcmd);

		$i = 0;
		$ok = FALSE;

		while (TRUE) {
		    if (file_exists($settings['pidfile']) && ($_pid = file_get_contents($settings['pidfile'])) && posix_kill($_pid,SIGHUP)) {
			$ok = TRUE;
			break;
		    }
		    usleep(500000);
		    if ($i > 10) break;
		    ++$i;
		}
		echo ($ok) ? "OK.\n" : "ERROR. Process hasn't daemonized. Try to run the following command manually and fix an error:\n".$cmd."\n";
	}
	break;

    case 'stop':
	echo '[STOP] Sending SIGTERM to '.$_pid.'... '.(($ok = ($_pid && posix_kill($_pid,SIGTERM))) ? 'OK.' : 'It seems that CuteBind is not running.')."\n";
	if ($ok) {
	    $i = 0;
	    while ($r = posix_kill($_pid,SIGHUP)) {
		usleep(500000);
		if ($i == 9) {
		    echo ' CuteBind master-process hasn\'t finish. Sending SIGKILL... '.(($ok = posix_kill($_pid,SIGKILL))?'OK.':'ERROR. Permissions?')."\n";
		    if ($ok) {
			if (!posix_kill($_pid,SIGHUP)) {
			    $running = FALSE; echo " Oh, his blood is on my hands :'(\n";
			} else {
			    $running = TRUE; echo "ERROR: Process alive. Permissions?\n";
			}
		    }
		    break;
		}
		++$i;
	    }
	    if (!$r) echo "\n";
	} else {
	    echo "\n";
	}
	break;

    case 'help':
	echo "CuteBind $ver. Made by gf@hackweb.org.\n";
	echo "Usage: cutebind (start|stop|restart|status|debug|configtest|help)\n";
	echo "    Optional comman-line parameters (will override values set in config).\n";
	echo "\t--pid-file='/path/to/pid-file'  - Alternative location and name for 'pid' file.\n";
	echo "\t--listen='127.0.0.1:53'         - Comma-separateted list of IP_address:port to listen on. Default is localhost:53 / 127.0.0.1\n";
	echo "\t--listen-port=53                - Default port number to listen on (only used if :port suffix above is not specified). Default is 53.\n";
	echo "\t--cutebind-path='cutebind'      - Set alternative path to cutebind's executable shell file.\n";
	echo "\t--config-file='/path/to/config.php'  - Alternative location and name of the configuration file.\n";
	echo "\t--logging=1                     - Logging. 1-Enable, 0-Disable\n";
	echo "\t--log-storage='/path/to/logs/%DATE=Y.m.d%.log'  - Log file location and name pattern.\n";
	echo "\t--set-user=cutebind             - Set user of master process (aka sudo).\n";
	echo "\t--set-group=cutebind            - Set group of master process (aka sudo).\n";
	echo "\t--tmp-file=/tmp/cutebind.tmp    - Temporary report file. CuteBind processes must have write access to this location.\n";
//	echo "\t--manual                        - Open the manual pages.\n";
	echo "\t--help                          - This help information.\n\n";
	break;

    default:
	echo "usage: cutebind (start|stop|restart|status|debug|configtest|help)\n";
    }	// switch()

?>
