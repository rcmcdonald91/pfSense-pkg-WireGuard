<?php
/*
 * wg.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/theonemcdonald)
 * Copyright (c) 2020 Ascrod
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
require_once('gwlb.inc');
require_once('util.inc');

// WireGuard includes
require_once('wireguard/wg_api.inc');
require_once('wireguard/wg_install.inc');
require_once('wireguard/wg_service.inc');
require_once('wireguard/wg_validate.inc');

global $wgg;

/*
 * This toggles a given tunnel based on index
 */
function wg_toggle_tunnel($tunnel_name) {
	global $wgg;

	// Make sure we have the latest info
	wg_globals();

	$changes = false;

	$input_errors = $pconfig = array();

	// Get the config array index
	$tun_idx = wg_get_tunnel_array_index($tunnel_name);

	// Make sure we have a valid tunnel in the xml
	if (isset($wgg['tunnels'][$tun_idx])) {

		$old_config = $wgg['tunnels'][$tun_idx];

		$enabled = ($tunnel['enabled'] == 'yes');

		if ($enabled && is_wg_tunnel_assigned($old_config['name'])) {

			$input_errors[] = 'Cannot disable a WireGuard tunnel while it is assigned as an interface.';

		}

		if (empty($input_errors)) {

			// Now we toggle the tunnel
			$wgg['tunnels'][$tun_idx]['enabled'] = ($old_config['enabled'] == 'yes') ? 'no' : 'yes';

			// Sync with configuration backend
			write_config("[{$wgg['pkg_names'][0]}] Tunnel {$tunnel['name']} deleted.");

			// Changes were made
			$changes = true;

			// Add tunnel to the list to apply
			wg_apply_list_append($pconfig['name'], 'tunnels');

		}

	}

	return array('input_errors' => $input_errors, 'changes' => $changes);

}

/*
 * This toggles a given peer based on peerid
 */
function wg_toggle_peer($peer_id) {
	global $wgg;

	// Make sure we have the latest info
	wg_globals();

	// Make sure we have a valid peer
	if (isset($wgg['peers'][$peer_id])) {

		// Toggle the peer
		$wgg['peers'][$peer_id]['enabled'] = ($wgg['peers'][$peer_id]['enabled'] == 'yes') ? 'no' : 'yes';

		// Sync with configuration backend
		write_config("[{$wgg['pkg_names'][0]}] Peer {$peer_id} deleted.");

		// Sync with the WireGuard backend
		wg_resync_peer($wgg['peers'][$peer_id]);

	}

}

/*
 * This deletes a given peer based on index
 */
function wg_delete_peer($peer_id) {
	global $wgg;

	wg_globals();

	if (isset($wgg['peers'][$peer_id])) {

		// We need to save this because we are about to unset it
		$tunnel_name = $wgg['peers'][$peer_id]['tun'];

		// Delete the peer
		unset($wgg['peers'][$peer_id]);

		// Sync with configuration backend
		write_config("[{$wgg['pkg_names'][0]}] Peer {$peer_id} deleted.");

		// Sync with the WireGuard backend
		wg_resync_tunnel($tunnel_name);

	}

}

/*
 * This deletes a given tunnel based on name
 */
function wg_delete_tunnel($tunnel_name) {
	global $wgg;

	// Make sure we have the latest info
	wg_globals();

	$changes = false;

	$input_errors = array();

	// Get the config array index
	$tun_idx = wg_get_tunnel_array_index($tunnel_name);

	// Make sure we have a valid tunnel
	if (isset($wgg['tunnels'][$tun_idx])) {

		$tunnel = $wgg['tunnels'][$tun_idx];

		// We can't delete assigned tunnels
		if (is_wg_tunnel_assigned($tunnel['name'])) {

			$input_errors[] = 'Cannot delete a WireGuard tunnel assigned to a pfSense interface.';

		}

		if (empty($input_errors)) {

			// Delete the tunnel
			unset($wgg['tunnels'][$tun_idx]);

			// Sync with configuration backend
			write_config("[{$wgg['pkg_names'][0]}] Tunnel {$tunnel['name']} deleted.");

			// Changes were made
			$changes = true;

			// Add tunnel to the list to apply
			wg_apply_list_append($pconfig['name'], 'tunnels');

		}

	}

	return array('input_errors' => $input_errors, 'changes' => $changes);

}

/*
 * This transforms a raw peer post consisting of repeatables 
 */
function wg_peer_allowedips($post) {

	// Convert the post into proper arrays
	$allowedips = wg_parse_post_repeatables($post, array('address', 'address_subnet', 'address_descr', 'address_route'));

	$ret_array = array();

	// Loop through each address entry
	foreach ($allowedips as $row) {

		// Remove any accidental whitespace
		$row['address'] = trim($row['address']);

		if (!empty($row['address'])) {

			$ret_array[] 	= array(
						'address' 	=> $row['address'], 
						'mask' 		=> $row['address_subnet'], 
						'descr' 	=> $row['address_descr'],
						'route' 	=> $row['address_route']);

		}

	}

	return $ret_array;

}

/*
 * This transforms a raw tunnel post consisting of repeatables 
 */
function wg_tunnel_addresses($post) {

	// Convert the post into proper arrays
	$addresses = wg_parse_post_repeatables($post, array('address', 'address_subnet', 'address_descr'));

	$ret_array = array();

	// Loop through each address entry
	foreach ($addresses as $row) {

		// Remove any accidental whitespace
		$row['address'] = trim($row['address']);

		if (!empty($row['address'])) {

			$ret_array[] 	= array(
						'address' 	=> $row['address'], 
						'mask' 		=> $row['address_subnet'], 
						'descr' 	=> $row['address_descr']);

		}

	}

	return $ret_array;

}

/*
 * This converts a raw form post containing any repeatables like addresses, subnets, and descriptions and returns an actual array
 */
function wg_parse_post_repeatables($post, $fields = null) {

	$ret_array = array();

	if (is_array($fields)) {

		foreach ($fields as $field) {

			$x = 0;

			while (!is_null($post["{$field}{$x}"])) {

				$ret_array[$x][$field] = $post["{$field}{$x}"];

				$x++;

			}

		}

	}

	return $ret_array;

}

/*
 * Takes a raw post for a peer, validates it, and saves it to the configuration system
 */
function wg_do_peer_post($post) {
	global $wgg;

	wg_globals();

	$pconfig = $input_errors = array();

	// Assume no changes will be made...
	$changes = false;

	$peer_idx = $post['index'];

	// We need to save the "old config" to compare against later...
	$pconfig = $old_config = $wgg['peers'][$peer_idx];

	wg_init_config_arr($pconfig, array('allowedips', 'row'));

	$pconfig['enabled'] 		= empty($post['enabled']) ? 'no' : $post['enabled'];

	$old_tun 			= $pconfig['tun'];

	$pconfig['tun'] 		= $post['tun'];

	$pconfig['descr'] 		= $post['descr'];

	$pconfig['endpoint'] 		= $post['endpoint'];

	$pconfig['port'] 		= empty($post['port']) ? $wgg['default_port'] : $post['port'];

	$pconfig['persistentkeepalive']	= $post['persistentkeepalive'];

	$pconfig['publickey'] 		= $post['publickey'];
	
	$pconfig['presharedkey']	= $post['presharedkey'];

	$pconfig['allowedips']['row'] 	= wg_peer_allowedips($post);

	// Looks like we have a dynamic endpoint, so clear endpoint or port variables before saving
	if (isset($post['dynamic']) && $post['dynamic'] == 'yes') {

		unset($pconfig['endpoint'], $pconfig['port']);

	}

	$input_errors = wg_validate_peer_post($pconfig);

	if (empty($input_errors)) {

		$wgg['peers'][$peer_idx] = $pconfig;

		// Sync with configuration backend
		write_config("[{$wgg['pkg_names'][0]}] Peer {$pconfig['descr']} updated.");

		// Check if anything actually changed or was this just a clean re-save?
		if (md5(serialize($old_config)) != md5(serialize($pconfig))) {

			// Config hashes mismatched, so we've got changes...
			$changes = true;

		}


	}

	return array('input_errors' => $input_errors, 'changes' => $changes, 'pconfig' => $pconfig);

}

/*
 * Takes a raw post for a tunnel, validates it, and saves it to the configuration system
 */
function wg_do_tunnel_post($post) {
	global $wgg;

	wg_globals();

	$pconfig = $input_errors = array();

	// Assume no changes will be made...
	$changes = false;

	$tun_idx = $post['index'];

	// We need to save the "old config" to compare against later...
	$pconfig = $old_config = $wgg['tunnels'][$tun_idx];

	wg_init_config_arr($pconfig, array('addresses', 'row'));

	$pconfig['name']		= empty($pconfig['name']) ? next_wg_if() : $pconfig['name'];

	$pconfig['enabled'] 		= empty($post['enabled']) ? 'no' : $post['enabled'];

	$pconfig['descr'] 		= $post['descr'];

	$pconfig['listenport'] 		= empty($post['listenport']) ? next_wg_port() : $post['listenport'];

	$pconfig['privatekey'] 		= $post['privatekey'];

	$pconfig['publickey'] 		= wg_gen_publickey($post['privatekey']);

	$pconfig['mtu'] 		= empty($post['mtu']) ? $wgg['default_mtu'] : $post['mtu'];

	$pconfig['addresses']['row'] 	= wg_tunnel_addresses($post);

	$input_errors 			= wg_validate_tunnel_post($pconfig, $tun_idx);

	if (empty($input_errors)) {

		$wgg['tunnels'][$tun_idx] = $pconfig;

		// Sync with configuration backend
		write_config("[{$wgg['pkg_names'][0]}] Tunnel {$pconfig['name']} updated.");

		// Check if anything actually changed or was this just a clean re-save?
		if (md5(serialize($old_config)) != md5(serialize($pconfig))) {

			// Config hashes mismatched, so we've got changes...
			$changes = true;

			// Add tunnel to the list to apply
			wg_apply_list_append($pconfig['name'], 'tunnels');

		}

	}

	return array('input_errors' => $input_errors, 'changes' => $changes, 'pconfig' => $pconfig);

}

function wg_apply_list_get($list, $delete_after_get = true) {
	global $wgg;

	$toapplylist = array();

	if (isset($wgg['applylist'][$list])) {

		$listpath = $wgg['applylist'][$list];

		if (file_exists($listpath)) {

			$toapplylist = unserialize(file_get_contents($listpath));

		}

		if ($delete_after_get) {

			unlink_if_exists($listpath);

		}

	}

	return $toapplylist;

}

function wg_apply_list_append($entry, $list) {
	global $wgg;

	$toapplylist = array();

	if (isset($wgg['applylist'][$list])) {

		$listpath = $wgg['applylist'][$list];

		if (file_exists($listpath)) {

			$toapplylist = unserialize(file_get_contents($listpath));

		}

		$toapplylist[] = $entry;

		file_put_contents($listpath, serialize($toapplylist));

	}

}

/*
 * This resyncs (i.e. wg syncconf) all configured tunnel interfaces
 */
function wg_tunnel_resync_all() {
	global $wgg;

	$ret_tunnels = array();

	// Let's assume everything will be fine
	$ret_code = 0;

	wg_resync();

	if (isset($wgg['tunnels']) && is_array($wgg['tunnels'])) {

		// Resync each tunnel
		foreach ($wgg['tunnels'] as $tunnel) {
			
			$build_status = wg_tunnel_resync($tunnel['name']);

			// Build an aggregated return code
			$ret_code |= $build_status['ret_code'];

			$ret_tunnels[] = array(
						'name' => $tunnel['name'],
						'ret_code' => $build_status['ret_code'], 
						'errors' => $build_status['errors'],
						'config' => $build_status['config']);

		}

	}

	return array('ret_code' => $ret_code, 'tunnels' => $ret_tunnels);

}

/*
 * This resyncs (i.e. wg syncconf) a specific tunnel interface by name
 */
function wg_tunnel_resync($tunnel_name) {
	global $wgg;

	wg_globals();

	$ret_code = 0;

	$errors = $tunnel = array();

	$tun_idx = wg_get_tunnel_array_index($tunnel_name);

	if (!isset($wgg['tunnels'][$tun_idx])) {
		
		$ret_code |= WG_ERROR_WG_ERROR_IF_NAME;
	
	}
	
	if (isset($wgg['tunnels'][$tun_idx])) {

		$tunnel = $wgg['tunnels'][$tun_idx];

		// Sync interface with WireGuard wg(8)
		if (wg_interface_syncconf($tunnel['name']) <> 0) {

			$ret_code |= WG_ERROR_IF_SYNC;
		
		}

	}

	// Now collect the errors...
	foreach ($wgg['error_flags']['tunnel'] as $error_mask => $error_text) {

		if (($ret_code & $error_mask) > 0) {

			$errors[$error_mask] = $error_text;

		}

	}

	return array('name' => $tunnel_name, 'ret_code' => $ret_code, 'errors' => $errors, 'config' => $tunnel);

}

/*
 * This builds configured tunnel interfaces
 * If $tunnels is empty, this will (re)build all tunnels.
 */
function wg_tunnel_build($tunnel_names = null) {
	global $wgg;

	$tunnels = array();

	// Let's assume everything will be fine
	$ret_code = 0;

	// Fetch and build latest config files
	wg_resync();

	// This is only necessary if the sevice is running
	if (wg_is_service_running()) {

		// Should we build all the tunnels?
		if (is_null($tunnel_names) || !is_array($tunnel_names)) {

			// Are there any tunnels to build?
			if (isset($wgg['tunnels']) && is_array($wgg['tunnels'])) {

				$tunnel_names = array_map(fn($x) => $x['name'], $wgg['tunnels']);
			
			} else {

				// Nope...
				$tunnel_names = array();

			}

		}

		// Build each tunnel
		foreach ($tunnel_names as $tunnel_name) {

			$tun_idx = wg_get_tunnel_array_index($tunnel_name);

			if (isset($wgg['tunnels'][$tun_idx])) {

				$tun_build_status = wg_tunnel_build_by_name($tunnel_name);

				// Build an aggregated return code
				$ret_code |= $tun_build_status['ret_code'];

				$tunnels[] = array(
						'name' => $tunnel_name,
						'ret_code' => $tun_build_status['ret_code'], 
						'errors' => $tun_build_status['errors'],
						'config' => $tun_build_status['config']);

			}

		}

	}

	return array('ret_code' => $ret_code, 'tunnels' => $tunnels);

}

/*
 * This builds a specific tunnel interface by name
 */
function wg_tunnel_build_by_name($tunnel_name) {
	global $wgg;

	wg_globals();

	$ret_code = 0;

	$errors = $tunnel = array();

	$tun_idx = wg_get_tunnel_array_index($tunnel_name);

	if (!isset($wgg['tunnels'][$tun_idx])) {
		
		$ret_code |= WG_ERROR_WG_ERROR_IF_NAME;
	
	}
	
	if (isset($wgg['tunnels'][$tun_idx])) {

		$tunnel = $wgg['tunnels'][$tun_idx];

		// Create the tunnel interface if it does not yet exist
		if (wg_interface_create($tunnel['name']) <> 0) {
			
			$ret_code |= WG_ERROR_IF_CREATE;
		
		}

		// Add the tunnel interface to the WireGuard interface group
		if (wg_interface_group_add($tunnel['name']) <> 0) {
			
			$ret_code |= WG_ERROR_IF_GROUP;
		
		}

		// Update the addresses on the tunnel interface
		if (wg_interface_update_addresses($tunnel['name']) <> 0) {
			
			$ret_code |= WG_ERROR_IF_ADDRESSES;
		
		}

		// Toggle the interface accordingly instead of tearing it down completely
		if (isset($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {

			if (wg_ifconfig_up_interface($tunnel['name']) <> 0) { 
				
				$ret_code |= WG_ERROR_IF_UP;
			
			}

		} else {

			if (wg_ifconfig_down_interface($tunnel['name']) <> 0) {
				
				$ret_code |= WG_ERROR_IF_DOWN;
			
			}
		}

		// Sync interface with WireGuard wg(8)
		if (wg_interface_syncconf($tunnel['name']) <> 0) {

			$ret_code |= WG_ERROR_IF_SYNC;
		
		}

	}

	// Now collect the errors...
	foreach ($wgg['error_flags']['tunnel'] as $error_mask => $error_text) {

		if (($ret_code & $error_mask) > 0) {

			$errors[$error_mask] = $error_text;

		}

	}

	return array('name' => $tunnel_name, 'ret_code' => $ret_code, 'errors' => $errors, 'config' => $tunnel);

}

function wg_resync() {
	global $wgg;

	// Create WireGuard configuration files
	wg_create_config_files();

	// Update the Unbound ACL
	wg_unbound_acl_update();

	// We don't want active tunnels when the service isn't running...
	if (is_module_loaded($wgg['kmod']) && !wg_is_service_running()) {

		wg_destroy_tunnels();

	}

}

function wg_get_enabled_tunnels() {
	global $wgg;

	wg_globals();

	$ret_tunnels = array();

	foreach ($wgg['tunnels'] as $tunnel) {

		if (isset($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {

			$ret_tunnels[] = $tunnel;

		}

	}

	return $ret_tunnels;

}


/*
 * (Re)creates configuration files based on the current configuration
 */
function wg_create_config_files($clean = true) {
	global $wgg;

	wg_globals();

	// Create configuration path if it is missing
	if (!file_exists($wgg['conf_path'])) {

		mkdir($wgg['conf_path'], 0700, true);

	} else {

		chmod($wgg['conf_path'], 0700);

	}

	// We almost always want to just overwrite the old configurations
	if ($clean) {

		wg_delete_config_files();

	}

	// Check if there are any configurations to write to disk
	if (isset($wgg['tunnels']) && is_array($wgg['tunnels'])) {

		foreach ($wgg['tunnels'] as $tunnel) {

			make_wg_conf($tunnel);

		}

	}

}

/* 
 * Remove all wg config files from any potential conf directory
 */
function wg_delete_config_files() {
	global $wgg;

	$confpaths = array();

	$confpaths = array_merge(array($wgg['conf_path']), $wgg['conf_paths_to_clean']);

	// Loop through each potential conf path and delete all .conf files
	foreach ($confpaths as $path) {

		unlink_if_exists("{$path}/*.conf");

	}

}

/* 
 * Wrapper to sanitize many variables at once
 * Call as wg_htmlspecialchars($var1, $var2, ... $varX)
 * Vars can be a mix of strings and arrays
 */
function wg_htmlspecialchars(&...$vars) {

	foreach ($vars as &$var) {

		if (isset($var) && is_array($var)) {

			array_walk($var, function(&$x) {

				$x = htmlspecialchars($x);
		
			});

			continue;
		
		}

		$var = htmlspecialchars($var);

	}

}

/* 
 * Wrapper to sanitize many variables at once
 * Call as wg_escapeshellargs($var1, $var2, ... $varX)
 * Vars can be a mix of strings and arrays
 */
function wg_escapeshellarg(&...$vars) {

	foreach ($vars as &$var) {

		if (isset($var) && is_array($var)) {

			array_walk($var, function(&$x) {

				$x = escapeshellarg($x);
		
			});

			continue;
		
		}

		$var = escapeshellarg($var);

	}

}

/* 
 * Removes any configuration xml paths as defined by $wgg['xml_conf_tags']
 */
function wg_remove_config_settings() {
	global $config, $wgg;

	$confpaths = array();

	$confpaths = array_merge(array($wgg['xml_path']), $wgg['xml_paths_to_clean']);

	// Loop through each potential conf path and unset it
	foreach ($confpaths as $path) {

		array_unset_value($config, $path);

	}

	// Now write out the new config to disk
	write_config("[{$wgg['pkg_names'][0]}] Package configuration removed");

}

/*
 * Writes a WireGuard configuration file for a given tunnel to the configuration path
 */
function make_wg_conf($tunnel) {
	global $wgg;

	$txt = "# This WireGuard config file has been created automatically. " .
	    	"Do not edit!\n";

	$txt .= "# Description: {$tunnel['descr']}\n\n";

	// Process Interfaces section
	$txt .= "[Interface]\n";

	if (!empty($tunnel['privatekey'])) {

		$txt .= "PrivateKey = {$tunnel['privatekey']}\n";

	}

	if (!empty($tunnel['listenport'])) {

		$txt .= "ListenPort = {$tunnel['listenport']}\n";

	}

	$txt .= "\n";

	// Process peers section
	$peers = wg_get_tunnel_peers($tunnel['name']);

	if (is_array($peers) && count($peers) > 0) {

		foreach ($peers as $peer) {

			if (isset($peer['enabled']) && $peer['enabled'] == 'yes') {

				$txt .= "# Peer: {$peer['descr']}\n";

				$txt .= "[Peer]\n";

				if (!empty($peer['publickey'])) {

					$txt .= "PublicKey = {$peer['publickey']}\n";

				}

				if (!empty($peer['presharedkey'])) {

					$txt .= "PresharedKey = {$peer['presharedkey']}\n";
				}

				
				if (is_array($peer['allowedips']['row'])) {

					$allowedips = implode(',', array_map(fn($x) => "{$x['address']}/{$x['mask']}", $peer['allowedips']['row']));

					$txt .= "AllowedIPs = {$allowedips}\n";

				}

				if (!empty($peer['endpoint'])) {
			
					$peer['endpoint'] = is_ipaddrv6($peer['endpoint']) ? "[{$peer['endpoint']}]" : $peer['endpoint'];

					$peer['port'] = empty($peer['port']) ? $wgg['default_port'] : $peer['port'];

					$txt .= "Endpoint = {$peer['endpoint']}:{$peer['port']}\n";

				}

				if (!empty($peer['persistentkeepalive'])) {

					$txt .= "PersistentKeepalive = {$peer['persistentkeepalive']}\n";
				}

				$txt .= "\n";

			}
			
		}

	}

	$conf_path = "{$wgg['conf_path']}/{$tunnel['name']}.conf";

	$old_mask = umask(077);

	file_put_contents($conf_path, $txt);

	umask($old_mask);

}

?>