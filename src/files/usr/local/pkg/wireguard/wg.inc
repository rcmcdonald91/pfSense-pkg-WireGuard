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
require_once('wg_api.inc');
require_once('wg_globals.inc');
require_once('wg_install.inc');
require_once('wg_extras.inc');
require_once('wg_validate.inc');

// Setup WireGuard tunnel
function wg_configure_if($tunnel, $conf_hard = true, $verbose = false) {
	global $config, $wgg;
	
	$verbose_pipe = ($verbose ? "" : " > /dev/null 2>&1");

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
	exec("{$wgg['ifconfig']} {$tunnel['name']} group {$wgg['ifgroupentry']['ifname']}" . $verbose_pipe);

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

function wg_delete_tunnel($tunidx) {
	global $config, $wgg;

	if ($config['installedpackages']['wireguard']['tunnel'][$tunidx]) {

		unset($ifname);

		unset($conf_path);

		if (isset($config['installedpackages']['wireguard']['tunnel'][$tunidx]['name'])) {

			$ifname = $config['installedpackages']['wireguard']['tunnel'][$tunidx]['name'];

		}
		
		if (isset($ifname)) {

			$conf_path = $wgg['conf_path'] . "/" . $ifname . ".conf";

		}

		// Delete the tunnel configuration entry
		unset($config['installedpackages']['wireguard']['tunnel'][$tunidx]);

		write_config("[WireGuard] tunnel {$index} updated.");

		// Delete the wg?.conf file

		if (isset($conf_path) && is_file($conf_path)) {

			unlink($conf_path);

		}

		// Destroy the deleted tunnel
		wg_destroy_if($ifname);
	}
}

// Write new tunnel values to the configuration system
function wg_do_post($post) {
	global $config, $wgg;

	init_config_arr(array('installedpackages', 'wireguard', 'tunnel'));

	$input_errors = array();

	$index = $post['index'];

	$pconfig = &$config['installedpackages']['wireguard']['tunnel'][$index];

	if (empty($pconfig['name'])) {

		$pconfig['name'] = next_wg_if();

	}

	if (empty($pconfig['mtu'])) {

		$pconfig['mtu'] = $wgg['default_mtu'];

	}

	$pconfig['enabled'] = empty($post['enabled']) ? 'no' : 'yes';

	$pconfig['descr'] = $post['descr'];

	// Tunnel section
	$pconfig['interface']['address'] = $post['address'];
	$pconfig['interface']['listenport'] = $post['listenport'];
	$pconfig['interface']['privatekey'] = $post['privatekey'];
	$pconfig['interface']['publickey'] = genPubKey($post['privatekey']);

	$pconfig['interface']['mtu'] = $post['mtu'];

	if (isset($post['endpoint0'])) {
		// Peers section
		$pconfig['peers'] = array();
		$pconfig['peers']['wgpeer'] = array();

		$idx = 0;

		for (;;) {
			if (!$post['publickeyp'.$idx] &&
			    !$post['endpoint'.$idx] &&
			    !$post['allowedips'.$idx] &&
			    !$post['descr'.$idx] &&
			    !$post['persistentkeepalive'.$idx]) {
				break;
			}

			$peer = array();
			$peer['publickey'] = $post['publickeyp' . $idx];
			$peer['endpoint'] = $post['endpoint' . $idx];
			$peer['allowedips'] = $post['allowedips' . $idx];
			$peer['descr'] = $post['descp' . $idx];
			$peer['persistentkeepalive'] = $post['persistentkeepalive' . $idx];
			$peer['presharedkey'] = $post['presharedkey' . $idx];
			$peer['port'] = $post['port' . $idx];
			$peer['peerwgaddr'] = $post['peerwgaddr' . $idx];

			$pconfig['peers']['wgpeer'][] = $peer;
			$idx++;
		}
	} else {
		unset($pconfig['peers']);
	}

	$input_errors = wg_validate_post($pconfig);

	if (!$input_errors) {
		$config['installedpackages']['wireguard']['tunnel'][$index] = $pconfig;
		write_config("[WireGuard] Tunnel {$pconfig['name']} (Index {$index}) updated.");
	}

	return(array('input_errors' => $input_errors, 'pconfig' => $pconfig));
}

function wg_resync($verbose = false) {
	global $config, $g, $wgg;

	// Write out configuration files to disk
	wg_create_config_files();

	// Attempt to reinstall the interface group to keep things clean
	wg_ifgroup_install();

	if ($g['wireguard_installing']) {

		update_status("\n  Configuring WireGuard tunnels...");

	}

	// Get a list of configured tunnels
	$wg_tunnels = $config['installedpackages']['wireguard']['tunnel'];

	if (is_array($wg_tunnels)) {

		foreach ($wg_tunnels as $tunnel) {

			if (isset($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {

				// Determine if we should configure hard or soft
				$conf_hard = (!is_wg_tunnel_assigned($tunnel) || !does_interface_exist($tunnel['name']));

				wg_configure_if($tunnel, $conf_hard, $verbose);

				$if_friendly = convert_real_interface_to_friendly_interface_name($tunnel['name']);

				interface_reconfigure($if_friendly);

			} else {

				// Attempt to destroy the WireGuard tunnel
				wg_destroy_if($tunnel, $verbose);

			}

			

		}

	}

	if ($g['wireguard_installing']) {

		update_status("done.\n");

		// We are no longer installing
		unset($g['wireguard_installing']);

	}

}

function wg_create_config_files($clean = true) {
	global $config, $wgg;

	$wg_tunnels = $config['installedpackages']['wireguard']['tunnel'];

	// We've got some tunnels to configure
	if (is_array($wg_tunnels)) {

		// Create configuration path if it is missing
		if (!file_exists($wgg['conf_path'])) {

			mkdir($wgg['conf_path'], 0700, true);

		} else {

			chmod($wgg['conf_path'], 0700);

		}

		// We almost always want to just overwrite the configurations
		if ($clean) {

			delete_wg_configs();

		}

		foreach ($wg_tunnels as $tunnel) {

			if (!empty($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {

				make_wg_conf($tunnel);

			}

		}

	}

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

	// We want to let pfSense handling routing.
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

	file_put_contents($wgg['conf_path'] . "/" . $tunnel['name'] . ".conf", $txt);

	chmod($wgg['conf_path'] . "/" . $tunnel['name'] . ".conf", 0600);
}

// Remove all wg config files from the conf directory
function delete_wg_configs() {
	global $wgg;

	unlink_if_exists("{$wgg['conf_path']}/*.conf");

}

// Return WireGuard tunnel networks for a given address family
function wg_get_tunnel_networks($family = 'both') {
	global $config;
	$wg_tunnel_networks = array();
	init_config_arr(array('installedpackages', 'wireguard', 'tunnel'));
	if (is_wg_enabled()) {
		foreach ($config['installedpackages']['wireguard']['tunnel'] as $wg) {
			if (empty($wg['enabled']) ||
			    empty($wg['interface']['address'])) {
				continue;
			}
			foreach(explode(',', $wg['interface']['address']) as $wga) {
				list($wgnet, $wgmask) = explode('/', trim($wga));
				if ((is_ipaddrv6($wgnet) && ($family == 'ipv4')) ||
				    (is_ipaddrv4($wgnet) && ($family == 'ipv6'))) {
					continue;
				}
				$network = gen_subnet($wgnet, $wgmask);
				$wg_tunnel_networks[] = "{$network}/{$wgmask}";
			}
		}
	}
	return $wg_tunnel_networks;
}

// Locate a viable remote gateway address for a WireGuard tunnel
// Fall back to using the tunnel address itself.
// https://redmine.pfsense.org/issues/11300
function wg_find_tunnel_gw($tunnel, $addr) {
	list($ip, $mask) = explode("/", trim($addr));
	// Loop through peers looking for a viable remote gateway address
	if (is_array($tunnel['peers']) &&
	    is_array($tunnel['peers']['wgpeer']) &&
	    count($tunnel['peers']['wgpeer']) > 0) {
		foreach ($tunnel['peers']['wgpeer'] as $peer) {
			// If this peer has no configured Peer WireGuard Address, skip it.
			if (empty($peer['peerwgaddr'])) {
				continue;
			}
			// Check each Peer WireGuard Address entry
			foreach (explode(',', $peer['peerwgaddr']) as $pwga) {
				// Ensure the address family of this entry matches the one we're seeking
				if (is_v4($ip) !== is_v4($pwga)) {
					continue;
				}
				// If there is a subnet mask, ditch it.
				list($pip, $pmask) = explode('/', trim($pwga));
				// Check that this address is in the desired subnet
				if (ip_in_subnet($pip, trim($addr))) {
					// We found a good candidate, return it
					return $pip;
				}
			}
		}
	}
	// If no viable candidate is found, return the tunnel address
	return $ip;
}

?>