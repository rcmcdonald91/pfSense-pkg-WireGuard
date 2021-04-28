<?php
/*
 * wg_api.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2021 R. Christian McDonald
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// pfSense includes
require_once('globals.inc');
require_once('config.inc');
require_once('pfsense-utils.inc');
require_once('system.inc');
require_once('pkg-utils.inc');
require_once('service-utils.inc');
require_once('util.inc');

// WireGuard includes
require_once('wireguard/wg_globals.inc');

// Wrapper for wg_status to output json
function wg_status_json($pretty = false) {

	$a_json = wg_status();

	return(json_encode($a_json, ($pretty ? JSON_PRETTY_PRINT : null) | JSON_UNESCAPED_SLASHES));

}

// Returns an associative array of current wg status
function wg_status() {
	global $wgg;

	$tunnel_keys = array('private_key', 'public_key', 'listen_port', 'fwmark');

	$peer_keys = array('public_key', 'preshared_key', 'endpoint', 'allowed_ips', 'latest_handshake', 'transfer_rx', 'transfer_tx', 'persistent_keepalive');

	$wg_output_rows = $a_ret = array();
	
	exec("{$wgg['wg']} show all dump", $wg_output_rows, $ret_code);

	// Bail out early if necessary
	if ($ret_code <> 0) { 
		
		return false; 
	
	}
	
	foreach ($wg_output_rows as $wg_index => $wg_row) {

		$tmp_tunnel = $tmp_peer = array();

		$a_device = explode("\t", $wg_row);

		$current_device = $a_device[0];

		if (strcmp($current_device, $last_device)) {

			foreach ($tunnel_keys as $index => $key) {

				$tmp_tunnel[$key] = $a_device[$index + 1];

			}

			$last_device = $a_device[0];

			// Add the tunnel to the array
			$a_ret[$current_device] = $tmp_tunnel;

		} else {

			foreach ($peer_keys as $index => $key) {

				$tmp_peer[$key] = $a_device[$index + 1];

			}

			$tmp_peer['latest_handshake_human'] = wg_human_time_diff($tmp_peer['latest_handshake']);

			$tmp_peer['name'] = wg_get_peer_name($tmp_peer['public_key'], $last_device);

			$tmp_peer['transfer_rx_human'] = format_bytes($tmp_peer['transfer_rx']);

			$tmp_peer['transfer_tx_human'] = format_bytes($tmp_peer['transfer_tx']);

			$tmp_peer['allowed_ips_hint'] = wg_format_address_hints($tmp_peer['allowed_ips']);

			// Add the peer to the array
			$a_ret[$last_device]['peers'][$a_device[1]] = $tmp_peer;
			
		}

	}

	return $a_ret;

}

function wg_format_address_hints($addresses) {

	$a_addresses = explode(',', $addresses);

	$address_count = count($a_addresses);

	return ($address_count > 1) ? "{$a_addresses[0]} (+{$address_count})" : $a_addresses[0];

}

function wg_truncate_pretty($str, $length) {

	$s_truncated = substr($str, 0, $length);

	$s_pretty_dots = (strlen($str) > $length) ? '...' : '';

	return "{$s_truncated}{$s_pretty_dots}";

}

function wg_human_time_diff($start_time, $end_time = 0, $from_epoch = false) {
	
	// If not supplied, use the current time
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

// Returns WireGuard peer name from a public key and tunnel name
function wg_get_peer_name($public_key, $tunnel) {
	global $wgg;

	foreach ($wgg['peers'] as $peer_id => $peer){

		if ($public_key == $peer['publickey'] && $tunnel = $peer['tun']) {

			return $peer['descr'];

		}

	}

	return false;

}

// Get WireGuard interface status
function wg_interface_status() {
	global $wgg;

	$if_group = escapeshellarg($wgg['if_group']);

	$status = array();
	exec("{$wgg['ifconfig']} -a -g {$if_group}", $status);

	$output = implode("\n", $status);
	return $output;

}

// Get various package infos and return an array
function wg_pkg_info() {
	global $wgg;

	$a_packages = $wgg['pkg_names'];

	// Escape each package element
	array_walk($a_packages, function(&$x) { $x = escapeshellarg($x); });
	
	// Construct an escaped sequence of packages to query
	$packages = implode(" ", $a_packages);

	exec("{$wgg['pkg']} query '%n\t%v\t%c' {$packages}", $output);

	foreach ($output as $key => $package) {

		$output[$key] = explode("\t", $package);

	}

	return $output;

}

// Generate private key
function wg_gen_keypair($json = false) {
	global $wgg;

	$privkey = exec("{$wgg['wg']} genkey");
	$pubkey = wg_gen_publickey($privkey);

	$res = array('privkey' => $privkey, 'pubkey' => $pubkey);
	return $json ? json_encode($res) : $res;

}

// Compose the public key from a provided private key
function wg_gen_publickey($privkey) {
	global $wgg;

	$privkey = escapeshellarg($privkey);

	$pubkey = exec("echo {$privkey} | {$wgg['wg']} pubkey");

	return $pubkey;

}

// Checks if a given private or public key is valid
function wg_is_valid_key($key) {
	global $wgg;

	$key = escapeshellarg($key);

	$retval = mwexec("echo {$key} | {$wgg['wg']} pubkey");

	return ($retval <> 0 ? false : true);

}

// This soft resyncs a given WireGuard Tunnel (i.e. wg syncconf wgX <(wg-quick strip wgX))
function wg_syncconf($tunnel) {
	global $wgg;

	// Assume we have an interface first
	$wg_ifname = $tunnel;

	// Looks like we have a tunnel structure
	if (is_array($tunnel) && isset($tunnel['name'])) {

		// Transform to an interface name
		$wg_ifname = $tunnel['name'];

	}

	// Escape the inner arguments
	$wg_ifname = escapeshellarg($wg_ifname);

	// Pass the stripped configuration to wg(8)
	$syncconf_command ="{$wgg['wg']} syncconf {$wg_ifname} <({$wgg['wg_quick']} strip {$wg_ifname})";

	// Escape the outer arguments
	$syncconf_command = escapeshellarg($syncconf_command);

	exec("{$wgg['bash']} -c {$syncconf_command}");

}

// Executes a wg-quick(8) action using a specified tunnel or interface
function exec_wg_quick_action($tunnel, $action, $verbose = false) {
	global $wgg;

	// Assume we have an interface first
	$wg_ifname = $tunnel;

	// Looks like we have a tunnel structure
	if (is_array($tunnel) && isset($tunnel['name'])) {

		// Transform to an interface name
		$wg_ifname = $tunnel['name'];

	}

	$action = escapeshellarg($action);

	$wg_ifname = escapeshellarg($wg_ifname);

	// Execute wg-quick(8) on the interface using the provided action 
	exec("{$wgg['wg_quick']} {$action} {$wg_ifname}" . verbose_pipe($verbose));

}

// Generate a pre-shared key
function wg_gen_psk() {
	global $wgg;

	$psk = exec("{$wgg['wg']} genpsk");

	return $psk;
	
}

// Return the next available WireGuard port
function next_wg_port() {
	global $config, $wgg;

	wg_globals();

	for ($idx = $wgg['default_port']; $idx < $wgg['max_port']; $idx++) {

		// Check to see if the port is already in use
		$found = false;

		foreach ($wgg['tunnels'] as $tunnel) {

			if ($tunnel['listenport'] == $idx) {

				$found = true;

				break;

			}

		}

		// If not, it can be used
		if (!$found) {

			return $idx;
			
		}

	}

	return $wgg['default_port'];

}

// Returns the array index of the given tunnel in the config, this isn't necessarily the interface number
function wg_get_tunnel_id($tunnel) {
	global $config, $wgg;

	// Assume we have an interface first
	$wg_ifname = $tunnel;

	// Looks like we have a tunnel structure
	if (is_array($tunnel) && isset($tunnel['name'])) {

		// Transform to an interface name
		$wg_ifname = $tunnel['name'];

	}

	if (isset($wgg['tunnels']) && is_array($wgg['tunnels'])) {

		foreach ($wgg['tunnels'] as $index => $tunnel) {

			if ($tunnel['name'] == $wg_ifname) {
				
				return $index;

			}

		}

	}

	return -1;

}

// Return the next available WireGuard interface
function next_wg_if() {
	global $config, $wgg;

	wg_globals();

	$used_ifs = array();

	foreach ($wgg['tunnels'] as $tunnel) {

		$used_ifs[] = $tunnel['name'];

	}

	for ($ifnum = 0; $ifnum < $wgg['max_tunnels']; $ifnum++) {

		$want_if = "{$wgg['if_prefix']}{$ifnum}";
		
		if (!in_array($want_if, $used_ifs)) {

			return $want_if;

		}

	}

	return -1;
	
}

function verbose_pipe($verbose) {

	return $verbose ? "" : " > /dev/null 2>&1";

}

?>