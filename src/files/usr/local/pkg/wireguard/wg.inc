<?php
/*
 * wg.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2021 R. Christian McDonald
 * Copyright (c) 2020 Ascord
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
require_once('globals.inc');
require_once('interfaces.inc');
require_once('pfsense-utils.inc');
require_once('pkg-utils.inc');
require_once('service-utils.inc');
require_once('system.inc');
require_once('util.inc');

// WireGuard includes
require_once('wireguard/wg_api.inc');
require_once('wireguard/wg_globals.inc');
require_once('wireguard/wg_guiconfig.inc');
require_once('wireguard/wg_install.inc');
require_once('wireguard/wg_validate.inc');

global $wgg;

/*
 * This toggles a given tunnel based on index
 */
function wg_toggle_tunnel($tun_id) {
	global $wgg;

	$input_errors = array();

	// Make sure we have the latest info
	wg_globals();

	// Make sure we have a valid tunnel
	if (isset($wgg['tunnels'][$tun_id])) {

		// We can't disable tunnels if they are assigned
		if (!is_wg_tunnel_assigned($wgg['tunnels'][$tun_id]['name'])) {

			// Now we toggle the tunnel
			$wgg['tunnels'][$tun_id]['enabled'] = ($wgg['tunnels'][$tun_id]['enabled'] == 'yes') ? 'no' : 'yes';

			// Write the configuration to disk
			write_config("[{$wgg['pkg_names'][0]}] Tunnel {$wgg['tunnels'][$tun_id]['name']} toggled.");

			// Create new configuration files
			wg_create_config_files();

		} else {

			$action_txt = ($wgg['tunnels'][$tun_id]['enabled'] == 'yes') ? 'disable' : 'enable';

			$input_errors[] = "Cannot {$action_txt} a WireGuard tunnel while it is assigned as an interface.";

		}

	}

	return $input_errors;

}

/*
 * This toggles a given peer based on index
 */
function wg_toggle_peer($peer_id) {
	global $config, $wgg;

	// Make sure we have the latest info
	wg_globals();

	// Make sure we have a valid peer
	if (isset($wgg['peers'][$peer_id])) {

		// Toggle the peer
		$wgg['peers'][$peer_id]['enabled'] = ($wgg['peers'][$peer_id]['enabled'] == 'yes') ? 'no' : 'yes';

		// Write the configuration to disk
		write_config("[{$wgg['pkg_names'][0]}] Peer {$peer_id} toggled.");

		// Create new configuration files
		wg_create_config_files();

	}

}

/*
 * This deletes a given peer based on index
 */
function wg_delete_peer($peer_id) {
	global $wgg;

	wg_globals();

	if (isset($wgg['peers'][$peer_id])) {

		unset($wgg['peers'][$peer_id]);

		write_config("[{$wgg['pkg_names'][0]}] Peer {$peer_id} deleted.");

		// Create new configuration files
		wg_create_config_files();


	}

}

/*
 * This deletes a given tunnel based on index
 */
function wg_delete_tunnel($tun_id) {
	global $wgg;

	wg_globals();

	unset($ifname, $conf_path);

	// Make sure we have a valid tunnel
	if (isset($wgg['tunnels'][$tun_id])) {

		// We can't delete assigned tunnels
		if (!is_wg_tunnel_assigned($wgg['tunnels'][$tun_id]['name'])) {

			if (isset($wgg['tunnels'][$tun_id]['name'])) {

				$ifname = $wgg['tunnels'][$tun_id]['name'];

			}
		
			if (isset($ifname)) {

				$conf_path = "{$wgg['conf_path']}/{$ifname}.conf";

			}

			// Delete the tunnel configuration entry
			unset($wgg['tunnels'][$tun_id]);

			write_config("[{$wgg['pkg_names'][0]}] Tunnel {$ifname} deleted.");

			// Create the new configuration files
			wg_create_config_files();
		
		} else {

			$input_errors[] = "Cannot delete a WireGuard tunnel assigned to a pfSense interface.";

		}

	}

	return $input_errors;

}

/*
 * This returns an array of peers for a given tunnel
 */
function wg_get_tunnel_peers($tunnel_name) {
	global $wgg;

	$a_ret = array();

	// Look through array of peers for matching tunnel name
	foreach ($wgg['peers'] as $peer_id => $peer) {

		if ($peer['tun'] == $tunnel_name) {

			// We need the array index for future manipulations
			$peer['index'] = $peer_id;

			$a_ret[] = $peer;

		}

	}

	// Return the list of filtered peers
	return $a_ret;

}

/*
 * This transforms a raw peer post consisting of repeatables 
 */
function wg_peer_addresses($post) {

	// Convert the post into proper arrays
	$addresses = wg_parse_post_repeatables($post, array('address', 'address_subnet', 'address_descr'));

	$ret_array = array();

	// Loop through each address entry
	foreach ($addresses as $address) {

		$tmp_subnet = "{$address['address']}/{$address['address_subnet']}";

		$ret_array[] = array('addr' => $tmp_subnet, 'descr' => $address['address_descr']);

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
	foreach ($addresses as $address) {

		$tmp_subnet = "{$address['address']}/{$address['address_subnet']}";

		$ret_array[] = array('addr' => $tmp_subnet, 'descr' => $address['address_descr']);

	}

	return $ret_array;

}

/*
 * This converts a raw form post containing any repeatables like addresses, subnets, and descriptions and returns an actual array
 */
function wg_parse_post_repeatables($post, $fields = null) {

	if (is_array($fields)) {

		$ret_array = array();

		foreach ($fields as $field) {

			$x = 0;

			while (!is_null($post["{$field}{$x}"])) {

				$ret_array[$x][$field] = $post["{$field}{$x}"];

				$x++;

			}

		}

		return $ret_array;

	}

	return false;

}

/*
 * Takes a raw post for a peer, validates it, and saves it to the configuration system
 */
function wg_do_peer_post($post) {
	global $wgg;

	wg_globals();

	$pconfig = $input_errors = array();

	$index = $post['index'];

	$pconfig = $wgg['peers'][$index];

	// Looks like we have a dynamic endpoint, so clear endpoint or port variables before saving
	if (isset($post['dynamic']) && $post['dynamic'] == 'yes') {

		unset($post['endpoint'], $post['port']);

	}

	$pconfig['enabled'] 		= empty($post['enabled']) ? 'no' : 'yes';

	$pconfig['tun'] 		= $post['tun'];

	$pconfig['descr'] 		= $post['descr'];

	$pconfig['endpoint'] 		= $post['endpoint'];

	$pconfig['port'] 		= $post['port'];

	$pconfig['persistentkeepalive']	= $post['persistentkeepalive'];

	$pconfig['publickey'] 		= $post['publickey'];
	
	$pconfig['presharedkey']	= $post['presharedkey'];

	wg_init_config_arr($pconfig, array('allowedips', 'item'));

	$pconfig['allowedips']['item'] 	= wg_peer_addresses($post);

	$input_errors = wg_validate_peer_post($pconfig);

	if (!$input_errors) {

		$wgg['peers'][$index] = $pconfig;

		write_config("[{$wgg['pkg_names'][0]}] Peer {$pconfig['descr']} updated.");

		wg_create_config_files();

	}

	return(array('input_errors' => $input_errors, 'pconfig' => $pconfig));

}

/*
 * Takes a raw post for a tunnel, validates it, and saves it to the configuration system
 */
function wg_do_tunnel_post($post) {
	global $wgg;

	wg_globals();

	$pconfig = $input_errors = array();

	$index = $post['index'];

	$pconfig = $wgg['tunnels'][$index];

	wg_init_config_arr($pconfig, array('addresses', 'item'));

	$pconfig['name']		= empty($pconfig['name']) ? next_wg_if() : $pconfig['name'];

	$pconfig['enabled'] 		= empty($post['enabled']) ? 'no' : 'yes';

	$pconfig['descr'] 		= $post['descr'];

	$pconfig['listenport'] 		= empty($post['listenport']) ? next_wg_port() : $post['listenport'];

	$pconfig['privatekey'] 		= $post['privatekey'];

	$pconfig['publickey'] 		= wg_gen_publickey($post['privatekey']);

	$pconfig['mtu'] 		= empty($post['mtu']) ? $wgg['default_mtu'] : $post['mtu'];

	$pconfig['addresses']['item'] 	= wg_tunnel_addresses($post);

	$input_errors 			= wg_validate_post($pconfig);

	if (!$input_errors) {

		$wgg['tunnels'][$index] = $pconfig;

		write_config("[{$wgg['pkg_names'][0]}] Tunnel {$pconfig['name']} updated.");

		wg_create_config_files();

	}

	return array('input_errors' => $input_errors, 'pconfig' => $pconfig);

}

/*
 * (Re)creates configuration files based on the current configuration
 */
function wg_create_config_files($clean = true) {
	global $wgg;

	wg_globals();

	// Check if there are any configurations to write to disk
	if (is_array($wgg['tunnels'])) {

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

		foreach ($wgg['tunnels'] as $tunnel) {

			if (!empty($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {

				make_wg_conf($tunnel);

			}

		}

	}

}

/* 
 * Remove all wg config files from any potential conf directory
 */
function wg_delete_config_files() {
	global $wgg;

	// Loop through each potential conf path and delete all .conf files
	foreach ($wgg['conf_paths_to_clean'] as $confpath) {

		unlink_if_exists("{$confpath}/*.conf");

	}

}

/* 
 * Removes any configuration xml paths as defined by $wgg['xml_conf_tags']
 */
function wg_remove_config_settings() {
	global $config, $wgg;

	// Loop through each potential conf path and unset
	foreach ($wgg['xml_paths_to_clean'] as $confpath) {

		array_unset_value($config, $confpath);

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

				
				if (is_array($peer['allowedips'])) {

					$allowedips = implode(',', array_map(fn($item) => $item['addr'], $peer['allowedips']['item']));

					$txt .= "AllowedIPs = {$allowedips}\n";

				}

				if (!empty($peer['endpoint'])) {
			
					$peer['endpoint'] = is_ipaddrv6($peer['endpoint']) ? "[{$peer['endpoint']}]" : $peer['endpoint'];

					$peer['port'] = empty($peer['port']) ? $wgg['default_port'] : $peer['port'];

					$txt .= "EndPoint = {$peer['endpoint']}:{$peer['port']}\n";

				}

				if (!empty($peer['persistentkeepalive'])) {

					$txt .= "PersistentKeepalive = {$peer['persistentkeepalive']}\n";
				}

				$txt .= "\n";

			}
			
		}

	}

	$conf_path = "{$wgg['conf_path']}/{$tunnel['name']}.conf";

	file_put_contents($conf_path, $txt);

	chmod($conf_path, 0600);

}

?>