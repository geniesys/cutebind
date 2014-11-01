<?php
function date_period($date_start, $date_finish)
{
 $st = explode('-', date('d-m-Y-H-i-s',$date_start));
 $fin = explode('-', date('d-m-Y-H-i-s',$date_finish));
 if (($seconds = $fin[5] - $st[5]) < 0) {$fin[4]--; $seconds += 60;}
 if (($minutes = $fin[4] - $st[4]) < 0) {$fin[3]--; $minutes += 60;}
 if (($hours = $fin[3] - $st[3]) < 0) {$fin[0]--; $hours += 24;}
 if (($days = $fin[0] - $st[0]) < 0) {$fin[1]--; $days += date('t', mktime(1, 0, 0, $fin[1], $fin[0], $fin[2]));}
 if (($months = $fin[1] - $st[1]) < 0) {$fin[2]--; $months += 12;}
 $years = $fin[2] - $st[2];
 return array($seconds,$minutes,$hours,$days,$months,$years);
}

function date_period_text($date_start,$date_finish)
{
 $result = date_period($date_start,$date_finish);
 $str  = '';
 if ($result[5] > 0) {$str .= $result[5].' year. ';}
 if ($result[4] > 0) {$str .= $result[4].' mon. ';}
 if ($result[3] > 0) {$str .= $result[3].' day. ';}
 if ($result[2] > 0) {$str .= $result[2].' hour. ';}
 if ($result[1] > 0) {$str .= $result[1].' min. ';}
 if ($result[0] > 0 or $str == '') {$str .= $result[0].' sec. ';}
 return trim($str);
}
?>