<?php
/*
 * wg_globals.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 R. Christian McDonald
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


// WireGuard includes
require_once('wireguard/wg_globals.inc');

function wg_truncate_pretty($str, $length) {

	$s_truncated = substr($str, 0, $length);

	$s_pretty_dots = (strlen($str) > $length) ? '...' : '';

	return "{$s_truncated}{$s_pretty_dots}";

}

// Returns the appropriate fa icon class for handshake status icon
function wg_handshake_status_icon($latest_handshake, $fa_icon = "fa-handshake") {
	global $wgg;

	$current_time = time();

	$latest_handshake = is_numeric($latest_handshake) ? $latest_handshake : $current_time;

	$diff_time = $current_time - $latest_handshake;

	$a_thresholds = $wgg['handshake_thresholds'];

	foreach ($a_thresholds as $threshold => $color) {

		$ret_color = ($diff_time <= threshold) ? $color : $ret_color;

	}

	$ret_html = "<i class=\"fa {$fa_icon} {$ret_color}\" style=\"vertical-align: middle;\"></i>;";

	return $ret_html;

}


function wg_human_time_diff($start_time, $end_time = 0, $from_epoch = false) {
	
	// If end time is not supplied, use the current time instead
	$end_time = empty($end_time) ? time() : $end_time;

	// If start time is zero, proceed unless we are actually interested in calculating time from epoch, probably not...
	$start_time = ($start_time > 0) ? $start_time : ($from_epoch ? $start_time : $end_time);

	$diff_time = abs($end_time - $start_time);

	$tokens = array (
		31536000 => 'year',
		2592000 => 'month',
		604800 => 'week',
		86400 => 'day',
		3600 => 'hour',
		60 => 'minute',
		1 => 'second'
	);

	foreach ($tokens as $unit => $text) {

		if ($diff_time < $unit) {
			
			continue;
			
		}

		$num_of_units = floor($diff_time / $unit);

		$plural = ($num_of_units > 1) ? 's' : '';
		
		return "{$num_of_units} {$text}{$plural}";

	}

	return "never";

}