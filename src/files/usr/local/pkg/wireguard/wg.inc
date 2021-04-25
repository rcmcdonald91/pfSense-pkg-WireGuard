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
require_once('wireguard/wg_install.inc');
require_once('wireguard/wg_validate.inc');

// Setup WireGuard tunnel
function wg_configure_if($tunnel, $conf_hard = true, $verbose = false) {
	global $config, $wgg;

	// Should we perform a hard reconfiguration
	if ($conf_hard) {

		// Destroy the interface first
		wg_destroy_if($tunnel, $verbose);

		// Then attempt to bring up interface using wg-quick(8)
		exec_wg_quick_action($tunnel, "up", $verbose);

	}

	// Now let's always soft configure the interface
	wg_syncconf($tunnel);

	// Add the interface to the interface group (i.e. WireGuard)
	mwexec("{$wgg['ifconfig']} {$tunnel['name']} group {$wgg['ifgroupentry']['ifname']}");

	// Get the tunnel interface friendly name if assigned
	$if_fname = convert_real_interface_to_friendly_interface_name($tunnel['name']);

	if(isset($if_fname)) {

		interface_reconfigure($if_fname);

		system_routing_configure($if_fname);
	
	}

}


// Remove WireGuard tunnel
function wg_destroy_if($tunnel, $verbose = false) {

	// Execute the wg-quick(8) way of tearing down an interface
	exec_wg_quick_action($tunnel, "down", $verbose);

	// Need to transform out of tunnel structure because pfSense_interface_destroy expects an ifname
	if (is_array($tunnel) && isset($tunnel['name'])) {

		$tunnel = $tunnel['name'];

	}

	// Now execute the pfSense way of tearing down an interface
	pfSense_interface_destroy($tunnel);

}

function wg_toggle_tunnel($tun_id) {
	global $wgg;

	// Make sure we have the latest info
	wg_globals();

	// Make sure we have a tunnel
	if (isset($wgg['tunnels'][$tun_id])) {

		$wgg['tunnels'][$tun_id]['enabled'] = ($wgg['tunnels'][$tun_id]['enabled'] == 'yes') ? 'no' : 'yes';

		write_config("[{$wgg['pkg_names'][0]}] Tunnel {$wgg['tunnels'][$tun_id]['name']} toggled.");
		
		wg_globals();

		wg_create_config_files();
		
		wg_ifgroup_install();

		$tunnel = $wgg['tunnels'][$tun_id];

		if (isset($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {

			$conf_hard = (!is_wg_tunnel_assigned($tunnel) || !does_interface_exist($tunnel['name']));

			wg_configure_if($tunnel, $conf_hard);

		} else {

			wg_destroy_if($tunnel);

		}

	}

}

function wg_delete_tunnel($tun_id) {
	global $config, $wgg;

	wg_globals();

	if (isset($wgg['tunnels'][$tun_id])) {

		$tmp_tunnel = $wgg['tunnels'][$tun_id];

		unset($ifname);

		unset($conf_path);

		if (isset($wgg['tunnels'][$tun_id]['name'])) {

			$ifname = $wgg['tunnels'][$tun_id]['name'];

		}
		
		if (isset($ifname)) {

			$conf_path = "{$wgg['conf_path']}/{$ifname}.conf";

		}

		// Delete the tunnel configuration entry
		unset($wgg['tunnels'][$tun_id]);

		write_config("[{$wgg['pkg_names'][0]}] Tunnel {$tmp_tunnel['name']} deleted.");

		// Delete the wg?.conf file
		if (isset($conf_path) && is_file($conf_path)) {

			unlink($conf_path);

		}

		// Destroy the deleted tunnel
		wg_destroy_if($ifname);

	}

}

function wg_get_tunnel_peers($tunnel) {
	global $config, $wgg;

	$a_ret = array();

	foreach ($wgg['peers'] as $peer_id => $peer) {

		if ($peer['tun'] == $tunnel) {

			$peer['index'] = $peer_id;

			$a_ret[] = $peer;

		}

	}

	return $a_ret;

}

function build_tun_list() {
	global $config, $wgg;

	$a_ret = array();

	$a_ret['unassigned'] = 'Unassigned';

	foreach ($wgg['tunnels'] as $tunnel) {

		$a_ret[$tunnel['name']] = "{$tunnel['name']} ({$tunnel['descr']})";	

	}

	return $a_ret;

}

// This converts a form post array containing addresses and subnets and returns an CIDR-formatted array
function wg_parse_post_addresses($post_array, $addrstr = 'address', $subnetstr = 'address_subnet') {

	$a_ret = array();

	$x = 0;

	while ($post_array["{$addrstr}{$x}"] && $post_array["{$subnetstr}{$x}"]) {

		$a_ret[] = "{$post_array["{$addrstr}{$x}"]}/{$post_array["{$subnetstr}{$x}"]}";

		$x++;

	}
	
	return $a_ret;

}

function wg_do_peer_post($post) {
	global $config, $wgg;

	wg_globals();

	$input_errors = array();

	$index = $post['index'];

	$pconfig = $wgg['peers'][$index];

	$pconfig['enabled'] 		= empty($post['enabled']) ? 'no' : 'yes';
	$pconfig['tun'] 		= $post['tun'];
	$pconfig['descr'] 		= $post['descr'];
	$pconfig['endpoint'] 		= $post['endpoint'];
	$pconfig['port'] 		= $post['port'];
	$pconfig['persistentkeepalive']	= $post['persistentkeepalive'];
	$pconfig['publickey'] 		= $post['publickey'];
	$pconfig['presharedkey']	= $post['presharedkey'];
	$pconfig['allowedips'] 		= implode(',', wg_parse_post_addresses($post));

	echo($pconfig['allowedips']);

	$input_errors = wg_validate_peer_post($pconfig);

	if (!$input_errors) {

		$wgg['peers'][$index] = $pconfig;

		write_config("[{$wgg['pkg_names'][0]}] Peer {$pconfig['descr']} updated.");

	}

	return(array('input_errors' => $input_errors, 'pconfig' => $pconfig));

}

// Write new tunnel values to the configuration system
function wg_do_post($post) {
	global $config, $wgg;

	wg_globals();

	$input_errors = array();

	$index = $post['index'];

	$pconfig = $wgg['tunnels'][$index];

	if (empty($pconfig['name'])) {

		$pconfig['name'] = next_wg_if();

	}

	if (empty($pconfig['mtu'])) {

		$pconfig['mtu'] = $wgg['default_mtu'];

	}

	$pconfig['enabled'] = empty($post['enabled']) ? 'no' : 'yes';

	$pconfig['descr'] = $post['descr'];

	// Tunnel section
	$pconfig['addresses'] = implode(',', wg_parse_post_addresses($post));
	$pconfig['listenport'] = $post['listenport'];
	$pconfig['privatekey'] = $post['privatekey'];
	$pconfig['publickey'] = wg_gen_publickey($post['privatekey']);

	$input_errors = wg_validate_post($pconfig);

	if (!$input_errors) {

		$wgg['tunnels'][$index] = $pconfig;

		write_config("[{$wgg['pkg_names'][0]}] Tunnel {$pconfig['name']} updated.");

	}

	return(array('input_errors' => $input_errors, 'pconfig' => $pconfig));

}



function wg_resync($verbose = false) {
	global $config, $g, $wgg;

	// Read latest settings
	wg_globals();

	// Write out configuration files to disk
	wg_create_config_files();

	// Attempt to reinstall the interface group to keep things clean
	wg_ifgroup_install();

	if ($g['wireguard_installing']) {

		update_status("\n  Configuring WireGuard tunnels...");

	}

	if (is_array($wgg['tunnels'])) {

		foreach ($wgg['tunnels'] as $tunnel) {

			if (isset($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {

				// Determine if we should configure hard or soft
				$conf_hard = (!is_wg_tunnel_assigned($tunnel) || !does_interface_exist($tunnel['name']));

				// Attempt to create the WireGuard tunnel
				wg_configure_if($tunnel, $conf_hard, $verbose);

			} else {

				// Attempt to destroy the WireGuard tunnel
				wg_destroy_if($tunnel, $verbose);

			}

		}

	}

	if ($g['wireguard_installing']) {

		update_status(" done.\n");

		// We are no longer installing
		unset($g['wireguard_installing']);

	}

}

function wg_create_config_files($clean = true) {
	global $config, $wgg;

	wg_globals();

	// We've got some tunnels to configure
	if (is_array($wgg['tunnels'])) {

		// Create configuration path if it is missing
		if (!file_exists($wgg['conf_path'])) {

			mkdir($wgg['conf_path'], 0700, true);

		} else {

			chmod($wgg['conf_path'], 0700);

		}

		// We almost always want to just overwrite the configurations
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

// Write each file
function make_wg_conf($tunnel) {
	global $wgg;

	$txt = "# This WireGuard config file has been created automatically. " .
	    "Do not edit!\n";

	$txt .= "# Description: {$tunnel['descr']}\n\n";

	// Process Interfaces section
	$txt .= "[Interface]\n";

	if (!empty($tunnel['interface']['privatekey'])) {
		$txt .= "PrivateKey = {$tunnel['interface']['privatekey']}\n";
	}

	if (!empty($tunnel['interface']['listenport'])) {
		$txt .= "ListenPort = {$tunnel['interface']['listenport']}\n";
	}

	if (!empty($tunnel['interface']['address'])) {
		$txt .= "Address = {$tunnel['interface']['address']}\n";
	}

	if (!empty($tunnel['interface']['mtu'])) {
		$txt .= "MTU = {$tunnel['interface']['mtu']}\n";
	}

	$txt .= "Table = off\n";

	$txt .= "\n";

	// Process peers section
	if (is_array($tunnel['peers']) && is_array($tunnel['peers']['wgpeer']) &&
	    count($tunnel['peers']['wgpeer']) > 0) {
		foreach ($tunnel['peers']['wgpeer'] as $peer) {
			$txt .= "# Peer: {$peer['descr']}\n";
			$txt .= "[Peer]\n";

			if (!empty($peer['publickey'])) {
				$txt .= "PublicKey = {$peer['publickey']}\n";
			}

			if (!empty($peer['endpoint'])) {
				$txt .= "EndPoint = ";
				$txt .= is_ipaddrv6($peer['endpoint']) ? "[{$peer['endpoint']}]" : $peer['endpoint'];
				$txt .= ":" . ((empty($peer['port'])) ? '51820' : $peer['port']) . "\n";
			}

			if (!empty($peer['allowedips'])) {
				$txt .= "AllowedIPs = {$peer['allowedips']}\n";
			}

			if (!empty($peer['persistentkeepalive'])) {
				$txt .= "PersistentKeepalive = " .
				    "{$peer['persistentkeepalive']}\n";
			}

			if (!empty($peer['presharedkey'])) {
				$txt .= "PresharedKey = " .
				    "{$peer['presharedkey']}\n";
			}

			$txt .= "\n";
		}
	}

	$conf_path = "{$wgg['conf_path']}/{$tunnel['name']}.conf";

	file_put_contents($conf_path, $txt);

	chmod($conf_path, 0600);

}

?>