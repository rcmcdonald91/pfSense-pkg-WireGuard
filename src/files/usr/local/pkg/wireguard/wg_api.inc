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

// Returns a massive associative array of current wg status
function wg_status() {
	global $wgg;

	$tunnel_keys = array('private_key', 'public_key', 'listen_port', 'fwmark');

	$peer_keys = array('public_key', 'preshared_key', 'endpoint', 'allowed_ips', 'latest_handshake', 'transfer_rx', 'transfer_tx', 'persistent_keepalive');
	
	exec("{$wgg['wg']} show all dump", $wg_output_rows, $ret_code);

	// Bail out early if necessary
	if ($ret_code <> 0) { 
		
		return false; 
	
	}

	$a_ret = array();
	
	foreach ($wg_output_rows as $wg_index => $wg_row) {

		$tmp_tunnel = $tmp_peer = array();

		$a_device = explode("\t", $wg_row);

		$current_device = $a_device[0];

		if (strcmp($current_device, $last_device)) {

			foreach ($tunnel_keys as $index => $key) {

				$tmp_tunnel[$key] = $a_device[$index + 1];

			}

			// Gets some extra information about tunnels not returned by `wg show all dump`
			$a_ret[$current_device]['descr'] = $wgg['tunnels'][wg_get_tunnel_id($current_device)];

			$a_tunnel_info = pfSense_get_interface_stats($current_device);

			$a_ret[$current_device]['transfer_rx'] = $a_tunnel_info['inbytes'];

			$a_ret[$current_device]['transfer_tx'] = $a_tunnel_info['outbytes'];

			// Add the tunnel to the array
			$a_ret[$current_device] = $tmp_tunnel;
			
			// Now provision an empty peer array
			$a_ret[$current_device]['peers'] = array();
			
			$last_device = $a_device[0];

		} else {

			foreach ($peer_keys as $index => $key) {

				$tmp_peer[$key] = $a_device[$index + 1];

			}

			// Gets some extra information about peers not returned by `wg show all dump`
			$a_peer_info = wg_get_peer_info($tmp_peer['public_key'], $last_device);

			$tmp_peer['descr'] = $a_peer_info['descr'];

			$tmp_peer['id'] = $a_peer_info['id'];

			$tmp_peer['allowed_ips_array'] = $a_peer_info['allowedips'];
			
			// Add the peer to the array
			$a_ret[$last_device]['peers'][$a_device[1]] = $tmp_peer;
			
		}


	}

	return $a_ret;

}

// Wrapper for wg_status to output json
function wg_status_json($pretty = false) {

	$a_json = wg_status();

	return json_encode($a_json, ($pretty ? JSON_PRETTY_PRINT : null) | JSON_UNESCAPED_SLASHES);

}

// Returns WireGuard peer info from a given public key and tunnel name
function wg_get_peer_info($public_key, $tunnel_name) {
	global $wgg;

	foreach ($wgg['peers'] as $peer_id => $peer){

		if ($public_key == $peer['publickey'] && $tunnel_name = $peer['tun']) {

			$ret_val = array('descr' => $peer['descr'], 'id' => $peer_id, 'allowedips' => $peer['allowedips']['item']);

			return $ret_val;

		}

	}

	return false;

}

function wg_get_tunnel($peer) {
	global $wgg;

	$tun_name = $peer['tun'];

	$tun_index = wg_get_tunnel_id($tun_name);

	return $wgg['tunnels'][$tun_index];

}

function wg_get_address_family($address) {

	if (is_v4($address)) {

		return 'inet';

	} elseif (is_v6($address)) {

		return 'inet6';

	} else {

		return false;

	}

}

function wg_ifconfig_del_address($ifname, $address) {
	global $wgg;

	// Gets the ifconfig address family while also validating the input at the same time
	if ($family_safe = wg_get_address_family($address)) {
		
		$ifname_safe = escapeshellarg($ifname);

		list($addr, $addr_subnet) = explode('/', $address);

		$address_safe = escapeshellarg($addr);

		$ret_val = mwexec("{$wgg['ifconfig']} {$ifname_safe} {$family_safe} {$address_safe} delete");

		return ($ret_val <> 0) ? false : true;

	}

	return false;

}

function wg_ifconfig_set_address($ifname, $address) {
	global $wgg;

	// Gets the ifconfig address family while also validating the input at the same time
	if ($family_safe = wg_get_address_family($address)) {
		
		$ifname_safe = escapeshellarg($ifname);

		$address_safe = escapeshellarg($address);

		$ret_val = mwexec("{$wgg['ifconfig']} {$ifname_safe} {$family_safe} {$address_safe} add");

		return ($ret_val <> 0) ? false : true;

	}

	return false;

}

function wg_ifconfig_down_interface($ifname) {
	global $wgg;

	$ifname_safe = escapeshellarg($ifname);

	$ret_val = mwexec("{$wgg['ifconfig']} {$ifname_safe} down");

	return ($ret_val <> 0) ? false : true;

}

function wg_ifconfig_up_interface($ifname) {
	global $wgg;

	$ifname_safe = escapeshellarg($ifname);

	$ret_val = mwexec("{$wgg['ifconfig']} {$ifname_safe} up");

	return ($ret_val <> 0) ? false : true;

}

/*
 * This updates the addresses of the specified interface without tearing it down
 */
function wg_interface_update_addresses($wg_ifname) {
	global $wgg;

	$index = wg_get_tunnel_id($wg_ifname);

	// Assigned tunnel interfaces are handled by pfSense and should be ignored here
	if (!is_wg_tunnel_assigned($wg_ifname)) {

		// Get an array of the current addresses assigned to the tunnel interface
		$current = pfSense_getall_interface_addresses($wg_ifname);

		// Get an array of the addresses to be assigned to the interface
		$desired = array_map(fn(&$x) => $x['addr'], $wgg['tunnels'][$index]['addresses']['item']);

		// Determine the addresses to remove
		$addresses_to_remove = array_diff($current, array_intersect($current, $desired));

		// Now remove them
		foreach ($addresses_to_remove as $address) {

			wg_ifconfig_del_address($wg_ifname, $address);

		}

		// Determine the addresses to add
		$addresses_to_add = array_diff($desired, array_intersect($current, $desired));

		// Now add them
		foreach ($addresses_to_add as $address) {

			wg_ifconfig_set_address($wg_ifname, $address);

		}

	// Now, we need to let pfSense handle assigned WireGuard tunnel interfaces
	} elseif (is_wg_tunnel_assigned($wg_ifname)) {

		if ($wg_pfsense_ifname = wg_get_pfsense_interface_name($wg_ifname)) {

			interface_configure($wg_pfsense_ifname, true);

		}

	}

}

function wg_interface_syncconf($wg_ifname) {
	global $wgg;

	$wg_ifname_safe = escapeshellarg($wg_ifname);

	$wg_conf_path_safe = escapeshellarg("{$wgg['conf_path']}/{$wg_ifname}.conf");

	$ret_val = mwexec("{$wgg['wg']} syncconf {$wg_ifname_safe} {$wg_conf_path_safe}");

	return ($ret_val <> 0) ? false : true;

}

function wg_interface_create_all() {
	global $wgg;

	$enabled_tunnels = wg_get_enabled_tunnels();

	foreach ($enabled_tunnels as $tunnel) {
		
		wg_interface_create($tunnel['name']);

		wg_interface_group_add($tunnel['name']);

		wg_interface_update_addresses($tunnel['name']);

	}

}

/*
 * This creates a WireGuard interface of a specified name and adds it to the WireGuard interface group
 */
function wg_interface_create($wg_ifname) {
	global $interface_arr_cache, $wgg;

	$wg_ifname_safe = escapeshellarg($wg_ifname);

	// We first check to see if the desired interface already exists, then we create it if it does not
	$ret_val = mwexec("{$wgg['ifconfig']} {$wg_ifname_safe} || {$wgg['ifconfig']} wg create name {$wg_ifname_safe}");
		
	return ($ret_val <> 0) ? false : true;

}

/*
 * This creates a WireGuard interface of a specified name and adds it to the WireGuard interface group
 */
function wg_interface_group_add($wg_ifname) {
	global $wgg;

	$wg_ifname_safe = escapeshellarg($wg_ifname);

	$wg_ifgroup_safe = escapeshellarg($wgg['if_group']);

	// We first check to see if the desired interface exists, then we add it to the group if it does
	$ret_val = mwexec("{$wgg['ifconfig']} {$wg_ifname_safe} && {$wgg['ifconfig']} {$wg_ifname_safe} group {$wg_ifgroup_safe}");
		
	return ($ret_val <> 0) ? false : true;

}

// Get WireGuard interface status
function wg_interface_status() {
	global $wgg;

	$if_group = escapeshellarg($wgg['if_group']);

	$status = array();

	exec("{$wgg['ifconfig']} -f inet:cidr,inet6:cidr -a -g {$if_group}", $status);

	$output = implode("\n", $status);

	$a_raw_interfaces = preg_split("/^(?![[:blank:]])/m", $output, 0, PREG_SPLIT_NO_EMPTY);

	$ret_val = array();

	foreach($a_raw_interfaces as $index => $raw_interface) {
        
		// match (tun_wg0)
		preg_match("/^(.*)\:\ flags/",$raw_interface,$interface_match);

		// flags=<(UP,etc)>		
		preg_match("/.*flags.*\<(.*)>.*/",$raw_interface,$flags_match);

		// match mtu: (1420)
		preg_match("/.*mtu\ ([0-9].*)/",$raw_interface,$mtu_match);

		// match description: (blah)
		preg_match("/.*description:\ (.*)/",$raw_interface,$descr_match);

		// match inet (0.0.0.0/0)
		preg_match_all("/.*inet\ (.*)/m",$raw_interface,$ip_match);

		$if = $index;
		
		$ret_val[$if]["interface"] = $interface_match[1];

		$ret_val[$if]["flags"] = $flags_match[1];

		$ret_val[$if]["mtu"] = $mtu_match[1];

		$ret_val[$if]["descr"] = $descr_match[1];


		foreach( $ip_match[1] as $key => $addr) {

			$ret_val[$if]["ips"][$key]['addr'] = $addr;

		}

	}

    return $ret_val;

}

// Get various package infos and return an associative array
function wg_pkg_info() {
	global $wgg;

	$ret_val = array();

	$a_fields = array('name'=> '%n', 'version' => '%v', 'comment' => '%c');

	$a_return_keys = array_values(array_flip($a_fields));

	$fields_safe = escapeshellarg(implode("\t", $a_fields));

	$a_packages = $wgg['pkg_names'];

	array_walk($a_packages, function(&$x) { $x = escapeshellarg($x); });
	
	$packages_safe = implode(" ", $a_packages);

	exec("{$wgg['pkg']} query {$fields_safe} {$packages_safe}", $packages, $ret_code);

	foreach ($packages as $pkg_index => $package) {

		$fields = explode("\t", $package);

		foreach ($fields as $field_index => $field) {

			$ret_val[$pkg_index][$a_return_keys[$field_index]] = $field;


		}

	}

	return ($ret_code <> 0) ? false : $ret_val;

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

?>