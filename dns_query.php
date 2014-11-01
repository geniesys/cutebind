<?php
require_once './include/core-bytes.php';
set_time_limit(0);
header('Content-type: text/plain');
$q = "\x8d\xef\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x71\x75\x69\x63\x6b\x74\x6f\x72\x72\x65\x6e\x74\x02\x72\x75\x00\x00\x01\x00\x01";

$dns = 'udp://81.31.39.230:53';
$socket = stream_socket_client($dns);
fwrite($socket,$q);
$data = fread($socket,1024);
var_dump(hecho($data));

$dns = 'udp://195.54.192.33:53';
$socket = stream_socket_client($dns);
fwrite($socket,$q);
$data = fread($socket,1024);
var_dump(hecho($data));

$result = dns_get_record("quicktorrent.ru.");
print_r($result);
?>