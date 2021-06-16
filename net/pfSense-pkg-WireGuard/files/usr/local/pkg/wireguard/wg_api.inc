<?php
/*
 * wg_api.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/theonemcdonald)
 * Copyright (c) 2021 Vajonam
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
require_once('config.inc');
require_once('interfaces.inc');		// interface_configure
require_once('util.inc');		// get_configured_interface_list_by_realif, mwexec
require_once('services.inc');
require_once('service-utils.inc');

// WireGuard includes
require_once('wireguard/wg_globals.inc');
require_once('wireguard/wg_install.inc');

/*
 * A wrapper for wg_show_dump to export everything plus extras for the status page
 */
function wg_get_status($json = false) {

	return wg_get_running_config($json);

}

/*
 * Returns a massive associative array of current wg status
 */
function wg_get_running_config($json = false) {
	global $wgg;

	$tunnel_output_keys = array('private_key', 'public_key', 'listen_port', 'fwmark');

	$peer_output_keys = array('public_key', 'preshared_key', 'endpoint', 'allowed_ips', 'latest_handshake', 'transfer_rx', 'transfer_tx', 'persistent_keepalive');

	$ret_config = $cmd_output_rows = array();

	exec("{$wgg['wg']} show all dump", $cmd_output_rows, $ret_code);

	if ($ret_code == 0) {

		foreach ($cmd_output_rows as $row) {

			$tmp_tunnel = $tmp_peer = array();

			$a_device = explode("\t", $row);

			$current_device = $a_device[0];

			if (strcmp($current_device, $last_device)) {

				foreach ($tunnel_output_keys as $key_index => $key) {

					$tmp_tunnel[$key] = $a_device[$key_index + 1];

				}

				// Gets some extra information about tunnels not returned by `wg show all dump`
				$tunnel_if_stats 		= pfSense_get_interface_stats($current_device);

				$tun_idx			= wg_get_tunnel_array_index($current_device);

				$tmp_tunnel['status'] 		= wg_interface_status($current_device) ? 'up' : 'down';

				$tmp_tunnel['transfer_rx'] 	= $tunnel_if_stats['inbytes'];

				$tmp_tunnel['transfer_tx'] 	= $tunnel_if_stats['outbytes'];

				$tmp_tunnel['inpkts']		= $tunnel_if_stats['inpkts'];

				$tmp_tunnel['outpkts']		= $tunnel_if_stats['outpkts'];

				$tmp_tunnel['mtu']		= $tunnel_if_stats['mtu'];

				$tmp_tunnel['desired_config']	= $wgg['tunnels'][$tun_idx];

				// Add the tunnel to the array
				$ret_config[$current_device] = $tmp_tunnel;

				// Now provision an empty peer array
				$ret_config[$current_device]['peers'] = array();

				$last_device = $a_device[0];

			} else {

				foreach ($peer_output_keys as $key_index => $key) {

					$tmp_peer[$key] = $a_device[$key_index + 1];

				}

				// Gets some extra information about peers not returned by `wg show all dump`
				$peer_idx = wg_get_peer_idx($tmp_peer['public_key'], $last_device);

				$tmp_peer['desired_config']	= $wgg['peers'][$peer_idx];

				// Add the peer to the array
				$ret_config[$last_device]['peers'][$a_device[1]] = $tmp_peer;

			}


		}

	}

	return ($json ? json_encode($ret_config, JSON_UNESCAPED_SLASHES) : $ret_config);

}

// Returns a peer array index by public key and tunnel name
function wg_get_peer_idx($public_key, $tunnel_name) {
	global $wgg;

	if (isset($wgg['peers']) && is_array($wgg['peers'])) {

		foreach ($wgg['peers'] as $peer_idx => $peer){

			if ($public_key == $peer['publickey'] && $tunnel_name = $peer['tun']) {

				return $peer_idx;

			}

		}

	}

	return -1;

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

function wg_ifconfig_del_address($wg_ifname, $masked_address) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	// Assume family validation will fail...
	$ret_code = 1;

	$cmd_output = $errors = array();

	// Gets the ifconfig address family while also validating the input at the same time
	if ($family = wg_get_address_family($masked_address)) {

		list($address, $address_subnet) = explode('/', $masked_address);

		$cmd = "{$wgg['ifconfig']} {$esa($wg_ifname)} {$esa($family)} {$esa($address)} delete 2>&1";

		exec($cmd, $cmd_output, $ret_code);

	}

	$ret_code = ($ret_code <> 0) ? WG_ERROR_IF_DELADDR : $ret_code;

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

function wg_ifconfig_set_address($wg_ifname, $masked_address, $ret_posix_style = true) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	// Assume family validation will fail...
	$ret_code = 1;

	$cmd_output = $errors = array();

	// Gets the ifconfig address family while also validating the input at the same time
	if ($family = wg_get_address_family($masked_address)) {

		$cmd = "{$wgg['ifconfig']} {$esa($wg_ifname)} {$esa($family)} {$esa($masked_address)} add 2>&1";

		exec($cmd, $cmd_output, $ret_code);

	}

	$ret_code = ($ret_code <> 0) ? WG_ERROR_IF_SETADDR : $ret_code;

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

function wg_ifconfig_down_interface($wg_ifname) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$cmd_output = $errors = $ret_array = array();

	$cmd = "{$wgg['ifconfig']} {$esa($wg_ifname)} down 2>&1";

	exec($cmd, $cmd_output, $ret_code);

	$ret_code = ($ret_code <> 0) ? WG_ERROR_IF_DOWN : $ret_code;

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

function wg_ifconfig_up_interface($wg_ifname) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$cmd_output = $errors = $ret_array = array();

	$cmd = "{$wgg['ifconfig']} {$esa($wg_ifname)} up 2>&1";

	exec($cmd, $cmd_output, $ret_code);

	$ret_code = ($ret_code <> 0) ? WG_ERROR_IF_UP : $ret_code;

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

/*
 * This updates the addresses of the specified interface without tearing it down
 */
function wg_interface_update_addresses($wg_ifname) {
	global $wgg;

	$tun_idx = wg_get_tunnel_array_index($wg_ifname);

	$tunnel = $wgg['tunnels'][$tun_idx];

	wg_init_config_arr($tunnel, array('addresses', 'row'));

	$cmds = array();

	// Assigned tunnel interfaces are handled by pfSense and should be ignored here
	if (!is_wg_tunnel_assigned($wg_ifname)) {

		// Get an array of the current addresses assigned to the tunnel interface
		$current = pfSense_getall_interface_addresses($wg_ifname);

		// Get an array of the addresses to be assigned to the interface
		$desired = array_map(fn(&$x) => "{$x['address']}/{$x['mask']}", $tunnel['addresses']['row']);

		// Determine the addresses to remove
		$addresses_to_remove = array_diff($current, array_intersect($current, $desired));

		// Now remove them
		foreach ($addresses_to_remove as $address) {

			if ($res = wg_ifconfig_del_address($wg_ifname, $address)) {

				

			}

		}

		// Determine the addresses to add
		$addresses_to_add = array_diff($desired, array_intersect($current, $desired));

		// Now add them
		foreach ($addresses_to_add as $address) {

			if ($res = wg_ifconfig_set_address($wg_ifname, $address)) {


			}

		}

	// Need to let pfSense handle the assigned interfaces
	} elseif (is_wg_tunnel_assigned($wg_ifname)) {

		if ($pfsense_if_name = wg_get_pfsense_interface_info($wg_ifname)) {

			interface_reconfigure($pfsense_if_name['name']);

		}

	}

	return (!empty($ret_array) ? $ret_array : null);

}

/* 
 * Translates WireGuard interface names to pfSense interface names and descriptions
 */
function wg_get_pfsense_interface_info($tunnel_name) {

	$ret_array = array();

	$iflist = get_configured_interface_list_by_realif(true);

	$ifdescr = get_configured_interface_with_descr(true);

	if (isset($iflist[$tunnel_name])) {

		$tmp_name = $iflist[$tunnel_name];

		$ret_array['name'] 	= $tmp_name;

		$ret_array['descr']	= $ifdescr[$tmp_name];

		return $ret_array;

	}

	// Consumers of this function always expect an array type
	return $ret_array;

}

/*
 * A wrapper for `wg set <wg_ifname> <key> <value>`
 */
function wg_set_interface_config($wg_ifname, $key, $value = null) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$cmd_output = $errors = array();

	$value = (!is_null($value)) ? " {$esa($value)}": $value;

	$cmd = "{$wgg['wg']} set {$esa($wg_ifname)} {$esa($key)}{$value} 2>&1";

	exec($cmd, $cmd_output, $ret_code);

	$errors = ($ret_code <> 0) ? $cmd_output : array();

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

/*
 * A wrapper for `wg set <wg_ifname> peer <public_key> <key> <value>`
 */
function wg_set_peer_config($wg_ifname, $public_key, $key = null, $value = null) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$cmd_output = $errors = array();

	$key = (!is_null($key)) ? " {$esa($key)}" : null;

	$value = (!is_null($value)) ? " {$esa($value)}" : null;

	$cmd = "{$wgg['wg']} set {$esa($wg_ifname)} peer {$esa($public_key)}{$key}{$value} 2>&1";

	exec($cmd, $cmd_output, $ret_code);

	$errors = ($ret_code <> 0) ? $cmd_output : array();

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

function wg_interface_syncconf($wg_ifname) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	wg_resync();

	$ret_code = 0;

	$cmd_output = $errors = array();

	$wg_conf_path = "{$wgg['conf_path']}/{$wg_ifname}.conf";

	if (file_exists($wg_conf_path)) {

		exec("{$wgg['wg']} syncconf {$esa($wg_ifname)} {$esa($wg_conf_path)}", $cmd_output, $ret_code);

		$ret_code = ($ret_code <> 0) ? WG_ERROR_IF_SYNC : $ret_code;

	}

	// Collect the errors
	$errors = wg_get_errors('interface', $ret_code);

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

/*
 * This creates a WireGuard interface of a specified name
 */
function wg_interface_create($wg_ifname) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$cmd_output = $errors = $ret_array = array();

	$cmd = "{$wgg['ifconfig']} {$esa($wg_ifname)} 2>&1";

	// First check if the interface already exists
	exec($cmd, $cmd_output, $ret_code);

	// If not, try to create it...
	if ($ret_code <> 0) {

		$ret_code = 0;

		$cmd_output = $errors = array();
		
		$cmd = "{$wgg['ifconfig']} wg create name {$esa($wg_ifname)} 2>&1";

		// Attempt to create the interface
		exec($cmd, $cmd_output, $ret_code);

		$ret_code = ($ret_code <> 0) ? WG_ERROR_IF_CREATE : $ret_code;

	}

	// Collect the errors
	$errors = wg_get_errors('interface', $ret_code);

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

function wg_get_errors($type, $ret_code) {
	global $wgg;

	$errors = array();

	if (isset($wgg['error_flags'][$type])) {

		// Now collect the errors...
		foreach ($wgg['error_flags'][$type] as $error_mask => $error_text) {

			if (($ret_code & $error_mask) > 0) {

				$errors[$error_mask] = $error_text;

			}

		}

	}

	return $errors;

}

/*
 * This destroys a WireGuard interface of a specified name
 */
function wg_interface_destroy($wg_ifname) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$cmd_output = $errors = array();

	$cmd = "{$wgg['ifconfig']} {$esa($wg_ifname)} destroy 2>&1";

	exec($cmd, $cmd_output, $ret_code);

	if ($ret_code <> 0) {

		$errors[WG_ERROR_IF_DESTROY] = $wgg['errors']['interface'][WG_ERROR_IF_DESTROY];

	}

	return array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

}

/*
 * Returns an array of the current WireGuard tunnel interfaces running as per ifconfig
 */
function wg_get_real_ifs() {
	global $wgg;

	$ret_array = array();

	exec("{$wgg['ifconfig']} -g wg", $ret_array, $ret_code);
	
	return ($ret_code == 0) ? $ret_array : array();

}

/*
 * This adds a WireGuard interface to the WireGuard interface group
 */
function wg_interface_group_add($wg_ifname) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$cmd_output = $errors = $ret_array = array();

	$cmd = "{$wgg['ifconfig']} {$esa($wg_ifname)} group {$esa($wgg['ifgroupentry']['ifname'])}";

	// Add interface to interface group
	exec($cmd, $cmd_output, $ret_code);

	$ret_code = ($ret_code <> 0) ? WG_ERROR_IF_GROUP : $ret_code;

	$ret_array = array('cmd' => $cmd, 'cmd_output' => $cmd_output, 'ret_code' => $ret_code, 'errors' => $errors);

	return (!empty($ret_array) ? $ret_array : null);

}

function wg_interface_status($wg_ifname) {

	$if_flags = wg_ifconfig_interface_flags($wg_ifname);

	return in_array("UP", $if_flags);

}

function wg_ifconfig_interface_flags($wg_ifname) {
	global $wgg;

	$esa = function($s) { return escapeshellarg($s); };

	$ret_code = 0;

	$flags = $cmd_output = array();

	exec("{$wgg['ifconfig']} {$esa($wg_ifname)}", $cmd_output, $ret_code);

	if (($ret_code == 0) && preg_match("/flags=.*<(?P<flags>.*)>/", $cmd_output[0], $matches)) {

		$flags = explode(',', $matches['flags']);

	}

	// Consumers of this function always expect an array type
	return $flags;

}

// Get various package infos and return an associative array
function wg_pkg_info() {
	global $wgg;

	$ret_array = array();

	$a_fields = array('name'=> '%n', 'version' => '%v', 'comment' => '%c');

	$a_return_keys = array_values(array_flip($a_fields));

	$field_string = implode("\t", $a_fields);

	$a_packages = $wgg['depends_names'];

	// Each package needs to be escaped individually before imploding
	wg_escapeshellarg($field_string, $a_packages);

	$packages_string = implode(" ", $a_packages);

	exec("{$wgg['pkg']} query {$field_string} {$packages_string}", $packages, $ret_code);

	if ($ret_code == 0) {

		foreach ($packages as $pkg_index => $package) {

			$fields = explode("\t", $package);

			foreach ($fields as $field_index => $field) {

				$ret_array[$pkg_index][$a_return_keys[$field_index]] = $field;

			}

		}

	}

	// Consumers of this function always expect an array type
	return $ret_array;

}

// Generate private key
function wg_gen_keypair($json = false) {
	global $wgg;

	$privkey = exec("{$wgg['wg']} genkey");

	$res = wg_gen_publickey($privkey, $json);

	return $res;

}

// Compose the public key from a provided private key
function wg_gen_publickey($privkey, $json = false) {
	global $wgg;

	// We want to pass the unmodified privkey through to the return array
	$safe_privkey = $privkey;

	$was_clamped 		= wg_is_key_clamped($privkey);

	$privkey_clamped 	= wg_clamp_key($privkey);

	wg_escapeshellarg($safe_privkey);

	$pubkey = exec("echo {$safe_privkey} | {$wgg['wg']} pubkey");

	$res = array('privkey' => $privkey, 'privkey_clamped' => $privkey_clamped, 'pubkey' => $pubkey, 'was_clamped' => $was_clamped);

	return $json ? json_encode($res) : $res;

}

/*
 * Reference0: https://lists.zx2c4.com/pipermail/wireguard/2021-June/006787.html
 * Reference1: https://git.zx2c4.com/wireguard-freebsd/tree/src/crypto.h#n100
 * 
 * Even though any 256-bit bitstring generated from a csprng is a fine private key,
 * the kernel clamps private keys according to the transformation implemented here.
 * Some WireGuard key generators aren't properly pre-clamping generated keys and this
 * can cause confusion for some users who might stumble across local .conf files 
 * and wg(8) output and see 'different' private keys, even though these keys result in
 * the same public key.
 * 
 * The way WireGuard is implemented, you can technically have two valid private keys,
 * one that is pre-clamped and one that is not, that can both result in the same public key.
 * 
 * These routines detect if the key is clamped or not, so we can at least include a note
 * in the .conf file so users who stumble onto them during troubleshooting won't freak out.
 * 
 * These routines might also become useful in the future for logging facilities.
 * 
 * Private keys and pre-shared Keys must undergo this transformaton.
 * 
 */
function wg_clamp_key($key) {

	if (wg_is_valid_key($key)) {

		$decoded_key = base64_decode($key);

		$key_bytes = array_slice(unpack("C*", "\0{$decoded_key}"), 1);

		$key_bytes[0] &= 248;

		$key_bytes[31] = ($key_bytes[31] & 127) | 64;

		$decoded_clamped_key = pack("C*", ...$key_bytes);

		return base64_encode($decoded_clamped_key);

	}

	return null;

}

/*
 * Checks if a given $key is clamped
 */
function wg_is_key_clamped($key) {

	if (wg_is_valid_key($key)) {

		return ($key == wg_clamp_key($key));

	}

	return true;

}

/*
 * Reference0: https://lists.zx2c4.com/pipermail/wireguard/2020-December/006222.html
 * 
 * Checks if a given private, public, or pre-shared key is valid
 */
function wg_is_valid_key($key) {

	return preg_match('/^[A-Za-z0-9+\/]{42}[A|E|I|M|Q|U|Y|c|g|k|o|s|w|4|8|0]=$/', $key);

}

/*
 * Generate a pre-shared key
 */
function wg_gen_psk() {
	global $wgg;

	$psk = exec("{$wgg['wg']} genpsk");

	return $psk;
	
}

/*
 * Return the next available WireGuard port
 */
function next_wg_port() {
	global $wgg;

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

// Wrapper to return just the xml array index
function wg_get_tunnel_array_index($tunnel_name) {
	global $wgg;

	$ret_val = array();

	if (is_array($wgg['tunnels'])) {

		foreach ($wgg['tunnels'] as $tun_idx => $tunnel) {

			if ($tunnel['name'] == $tunnel_name) {

				return $tun_idx;

			}

		}

	}

	return -1;

}

// Return the next available WireGuard interface
function next_wg_if() {
	global $wgg;

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

// Check if wg tunnel is assigned to an interface
function is_wg_tunnel_assigned($tunnel_name, $disabled = true) {

	$if_list = get_configured_interface_list_by_realif($disabled);

	$is_assigned = array_key_exists($tunnel_name, $if_list);

	return $is_assigned;

}

/*
 * Check if a wg tunnel is valid
 */
function wg_is_valid_tunnel($tunnel_name, $running_state = false) {
	global $wgg;

	$tunnel_names = array();

	if (isset($wgg['tunnels']) && is_array($wgg['tunnels']) && !$running_state) {

		// Checks desired state tunnels
		$tunnel_names = array_map(fn($x) => $x['name'], $wgg['tunnels']);

	} elseif ($running_state) {

		// Checks running state tunnels
		$tunnel_names = wg_get_real_ifs();
	}

	return in_array($tunnel_name, $tunnel_names);

}

// Check if at least one tunnel is assigned
function is_wg_assigned($disabled = true) {
	global $wgg;

	// Assume that no tunnels are assigned
	$is_assigned = false;

	$if_list = get_configured_interface_list_by_realif($disabled);

	foreach ($if_list as $realif => $name) {

		// We found one, no need to keep checking
		if (substr($realif, 0, strlen($wgg['if_prefix'])) == $wgg['if_prefix']) {

			$is_assigned = true;

			break;

		}

	}

	return $is_assigned;

}

// Check if at least one tunnel is enabled
function is_wg_enabled() {
	global $config, $wgg;

	wg_globals();

	if (is_array($wgg['tunnels'])) {

		foreach ($wgg['tunnels'] as $tunnel) {

			if (empty($tunnel['enabled'])) {

				continue;

			}

			return true;

		}

	}

	return false;
	
}

/*
 * This returns an array of peers for a given tunnel
 */
function wg_get_tunnel_peers($tunnel_name) {
	global $wgg;

	wg_globals();

	$ret_peers = array();

	$tun_idx = wg_get_tunnel_array_index($tunnel_name);

	if (isset($wgg['tunnels'][$tun_idx])) {

		if (isset($wgg['peers']) && is_array($wgg['peers'])) {

			// Look through array of peers for matching tunnel name
			foreach ($wgg['peers'] as $peer_idx => $peer) {

				if ($peer['tun'] == $tunnel_name) {

					// We need the array index for future manipulations
					$peer['index'] = $peer_idx;

					$ret_peers[$peer['publickey']] = $peer;

				}

			}

		}

	}

	// Return the list of filtered peers
	return $ret_peers;

}

/* 
 * Return WireGuard tunnel networks for a given address family
 */
function wg_get_tunnel_networks($family = 'both') {
	global $config, $wgg;

	$wg_tunnel_networks = array();

	if (is_wg_enabled()) {

		foreach ($wgg['tunnels'] as $tunnel) {

			if (!empty($tunnel['addresses']['row']) && is_array($tunnel['addresses']['row'])) {

				foreach ($tunnel['addresses']['row'] as $address) {

					$masked_address = "{$address['address']}/{$address['mask']}";

					if ((is_ipaddrv6($masked_address) && ($family == 'ipv4')) ||
						(is_ipaddrv4($masked_address) && ($family == 'ipv6'))) {

						continue;

					}

					if (is_subnet($masked_address)) {

						$network = gen_subnet($address['address'], $address['mask']);

						$wg_tunnel_networks[] 	= array(
										'network' => $network, 
										'mask' => $address['mask'],
										'tun' => $tunnel['name'],
										'descr' => $tunnel['descr']);

					}

				}

			}

		}

	}

	return $wg_tunnel_networks;

}

?>