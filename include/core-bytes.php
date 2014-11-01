<?php		// Various conversion and parsing functions to work with DNS packets.

function _labels($q) {
	if(! is_string($q)) {
	    echo '_labels() - Expect $q to be a string but got an ';
	    print_r($q);
	}
	$e = explode('.',$q);
	$r = '';
	for ($i = 0, $s = sizeof($e); $i < $s; ++$i) {
	  $r .= chr(strlen($e[$i])).$e[$i];
	}
	if (substr($r,-1) !== "\x00") $r .= "\x00";
	return $r;
}

function _LV($string,$len=1,$lrev=FALSE) {
	$l = i2b($len,strlen($string));
	if ($lrev) {$l = strrev($l);}
	return $l.$string;
}

function _LVnull($str)	{return _LV($str."\x00",2,TRUE);}
function _byte($int)	{return i2b(1,$int);}
function _word($int)	{return i2b(2,$int);}
function _wordl($int)	{return strrev(_word($int));}
function _dword($int)	{return i2b(4,$int);}
function _dwordl($int)	{return strrev(_dword($int));}
function _qword($int)	{return i2b(8,$int);}
function _qwordl($int)	{return strrev(_qword($int));}

function _get_byte(&$p)			{$r = bytes2int($p{0}); $p = substr($p,1); return intval($r);}
function _get_word(&$p,$l=FALSE)	{$r = bytes2int(substr($p,0,2),!!$l); $p = substr($p,2); return intval($r);}
function _get_dword(&$p,$l=FALSE)	{$r = bytes2int(substr($p,0,4),!!$l); $p = substr($p,4); return intval($r);}
function _get_qword(&$p,$l=FALSE)	{$r = bytes2int(substr($p,0,8),!!$l); $p = substr($p,8); return intval($r);}
function _get_str_qword(&$p,$l=FALSE)	{$r = substr($p,0,8); if ($l) {$r = strrev($r);} $p = substr($p,8); return $r;}

function _get_LV(&$p,$l=1,$nul=FALSE,$lrev=FALSE) {
	$s = b2i(substr($p,0,$l),!!$lrev);$p = substr($p,$l);
	if ($s == 0) return '';
	
	if (strlen($p) < $s) {
	    echo("_get_LV error: Stack length (".strlen($p)."): ".hecho($p).", must be >= string length (".$s.")");
	} elseif ($nul) {
	  if ($p{$s-1} != "\x00") {
	      echo("_get_LV error: Wrong end of NUL-string (".hecho($p{$s-1})."), len ".$s." ");
	  } else {
	    $d = $s-1; if ($d < 0) {$d = 0;} $r = substr($p,0,$d); $p = substr($p,$s);
	  }
	} else {
	    $r = substr($p,0,$s); $p = substr($p,$s);
	}
	return $r;
}

function int2bytes($len,$int=0x00) {
	$hexstr = dechex($int);
	if ($len === NULL) {
	    if (strlen($hexstr) % 2) $hexstr = "0".$hexstr;
	} else {
	    $hexstr = str_repeat("0",$len*2-strlen($hexstr)).$hexstr;
	}
	$bytes = strlen($hexstr)/2;
	$bin = "";
	for($i=0;$i<$bytes;$i++) {
	    $bin .= chr(hexdec(substr($hexstr,$i*2,2)));
	}
	return $bin;
}

function _flags2bitarray($flags,$len=4) {
	$ret = 0;
	foreach($flags as $v) {$ret |= $v;}
	return i2b($len,$ret);
}

function i2b($bytes,$val=0) {return int2bytes($bytes,$val);}

function bytes2int($str,$l=FALSE) {
	if ($l) $str = strrev($str);
	$dec = 0;
	$len = strlen($str);
	for($i=0;$i<$len;$i++) {
	    $dec += ord(substr($str,$i,1))*pow(256,$len-$i-1);
	}
	return $dec;
}

function b2i($hex=0,$l=FALSE) {
	return bytes2int($hex,$l);
}

function bitmap2bytes($bitmap,$check_len = 0) {
	$r = '';
	$bitmap = str_pad($bitmap,ceil(strlen($bitmap)/8)*8,'0',STR_PAD_LEFT);
	for ($i = 0, $n = strlen($bitmap)/8; $i < $n; ++$i) {
		$r .= chr((int) bindec(substr($bitmap,$i*8,8)));
	}
	if ($check_len && (strlen($r) != $check_len)) {echo "Warning! Bitmap incorrect.\n";}
	return $r;
}

function getbitmap($byte) {
	return sprintf('%08b',$byte);
}

?>