<?php
set_time_limit(0);
header('Content-type: text/plain');
$st = microtime(TRUE);
$dns = 'udp://192.168.1.16:53';
$requests = 1000;
$success = 0;
for ($i = 0; $i < $requests; ++$i)
{
 $socket = stream_socket_client($dns);
 fwrite($socket,"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x79\x61\x02\x72\x75\x00\x00\x01\x00\x01");
 if (strlen(fread($socket,1024)) >= 12) {++$success;}
}
$time = microtime(TRUE)-$st;
echo 'Total time: '.round($time,2).' ('.round($time/$requests,8)." per query)\n";
echo 'Requests: '.$requests.'. Success: '.$success."\n";
echo round($requests/$time,2)." per second\n";

?>