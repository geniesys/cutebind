<?php
/*
	Custom resolver example
*/
function resolver(&$q,&$a,$init = FALSE)
{
	global $settings;
	static $db = NULL;

	if ($db === NULL) {
		$p = parse_url($settings['dbaddr']);
		$db = mysql_connect($p['host'].':'.(isset($p['port'])?$p['port']:''),$p['user'],isset($p['pass'])?$p['pass']:'');
		mysql_select_db(trim($p['path'],'/'),$db);
	}

	static $geoip_isp = NULL;
	if ($geoip_isp  === NULL) {
		require_once "Net/GeoIP.php";
		$geoip_isp = Net_GeoIP::getInstance(COREBIND_ROOT.'GeoIPISP/GeoIPISP.dat');
	}

	if ($init) return;

	if ($q->QTYPE != 'A') return FALSE;

	if (preg_match('~(?:^|\.|\-)(?:0x([\da-f]{40})[\.\-])?(?:0?x)?(?:([\da-f]{8})|(\d+\-\d+\-\d+\-\d+))[\.\-](?:0?x)?(?:([\da-f]{8})|(\d+\-\d+\-\d+\-\d+))'.$settings['cuteresolve_domains'].'~i',$q->host,$m))
	{
		$peer_id = isset($m[1]) ? strtolower($m[1]) : '';
		$m_in_ip = isset($m[2]) ? $m[2]:'';
		$m_in_ip_p = isset($m[3])?$m[3]:'';
		if ($m[1] !== '') {
			$in_ip = hexdec(substr($m_in_ip,0,2)).'.'.hexdec(substr($m_in_ip,2,2)).'.'.hexdec(substr($m_in_ip,4,2)).'.'.hexdec(substr($m_in_ip,6,2));
		} else {
			$in_ip = str_replace('-','.',$m_in_ip_p);
		}

		$m_ex_ip = isset($m[4])?$m[4]:'';
		$m_ex_ip_p = isset($m[5])?$m[5]:'';
		if ($m_ex_ip !== '') {
			$ex_ip = hexdec(substr($m_ex_ip,0,2)).'.'.hexdec(substr($m_ex_ip,2,2)).'.'.hexdec(substr($m_ex_ip,4,2)).'.'.hexdec(substr($m_ex_ip,6,2));
		} else {
			$ex_ip = str_replace('-','.',$m_ex_ip_p);
		}

		if ($m_peer !== '')
		{
			if ($q->peer_IP == $ex_ip)
			{
				$sql = 'REPLACE INTO `peers` SET `peer_id` = \''.mysql_escape_string($peer_id).'\''
				       .', `ctime` = '.time()
			               .', `external_ip` = '.ip2long($ex_ip)
			               .', `internal_ip` = '.ip2long($in_ip);

				if (!mysql_query($sql,$db)) exit(mysql_error());
				$q->IP = $in_ip;
				return TRUE;
			} else {
				$result = mysql_query('SELECT * FROM `peers` WHERE `peer_id` = \''.mysql_escape_string($peer_id).'\'');
				if ($row = mysql_fetch_assoc($result)) {
					return $row[$result];
				}
			}
		}

		if ($q->peer_IP == $ex_ip) {
			$q->IP = $in_ip;
		}
		//elseif ($q->peer_ip == $in_ip) {$q->IP = $in_ip;}
		else {
			$q->peer_ISP  = NULL;
			$q->ex_ip_ISP = NULL;
			try
			{
				$q->peer_ISP  = $geoip_isp->lookupOrg($q->peer_IP);
				$q->ex_ip_ISP = $geoip_isp->lookupOrg($q->ex_ip);
			} catch (Exception $e) {}

			if (($q->peer_ISP === NULL) || ($q->ex_ip_ISP === NULL))
			{
				$ex_host = gethostbyaddr($ex_ip);
				$q->peer_host = gethostbyaddr($q->peer_IP);
				$ex_host_a = explode('.',strtolower($ex_host));
				$s = sizeof($ex_host_a);
				$peer_host_a = explode('.',strtolower($q->peer_host));
				if (($q->peer_host[$s-2] == $ex_host_a[$s-2]) && ($peer_host_a[$s-1] == $ex_host_a[$s-1])) {
					$q->IP = $q->in_ip;
				} else {
					$q->IP = $q->ex_ip;
				}
			} elseif ($q->peer_ISP == $q->ex_ip_ISP) {
				$q->IP = $q->in_ip;
			} else {
				$q->IP = $q->ex_ip;
			}

			var_dump($q->peer_ISP);
			var_dump($q->ex_ip_ISP);
		}
		return TRUE;
	}
	return FALSE;
}
?>