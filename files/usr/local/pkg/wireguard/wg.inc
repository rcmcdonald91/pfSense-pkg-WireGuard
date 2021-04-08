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

require_once('globals.inc');
require_once('config.inc');
require_once('pfsense-utils.inc');
require_once('system.inc');
require_once('pkg-utils.inc');
require_once('service-utils.inc');
require_once('util.inc');

require_once('wg_api.inc');
require_once('wg_validate.inc');

global $wgifgroup;
$wgifgroup = 'WireGuard';

// Setup all WireGuard tunnels
function wg_configure() {
	global $config;

	if (!is_array($config['installedpackages']['wireguard']['tunnel'])) {
		return;
	}

	wg_create_config_files();

	$tunnel =[];
	foreach ($config['installedpackages']['wireguard']['tunnel'] as $tunnel) {
		if (isset($tunnel['enabled']) && $tunnel['enabled'] == 'yes') {
			wg_configure_if($tunnel['name']);
		} else {
			wg_destroy_if($tunnel['name']);
		}
	}

	wg_write_rcfile();

}

function wg_write_rcfile() {
	global $config, $wgconfpath, $wgquickpath, $wgifgroup; 

	$wgconfigs = glob("{$wgconfpath}/*.conf");

	$rcfilepath = '/usr/local/etc/rc.d/wireguard';

	// Probably not necessary
	unlink_if_exists('$rcfilepath');

	// This ensures that write_rcfile will always create the file
	$start = $stop = ['# DO NOT REMOVE'];

	foreach ($wgconfigs as $wgconfig) {
		$wg_ifname = basename($wgconfig, '.conf');
		array_push($start, "{$wgquickpath} up {$wg_ifname} && ifconfig {$wg_ifname} group {$wgifgroup} && /etc/rc.filter_configure");
		array_push($stop, "{$wgquickpath} down {$wg_ifname}");
	}

	$rcfile = [];

	$rcfile['file'] = 'wireguard';
	$rcfile['start'] = implode("\n\t", $start);
	$rcfile['stop'] = implode("\n\t", $stop);

	write_rcfile($rcfile);

	// for good measure
	chmod($rcfilepath, 0755);

}

// Setup WireGuard tunnel
function wg_configure_if($wg_ifname, $destroyfirst = true, $verbose = false) {
	global $config, $wgconfpath, $wgquickpath, $wgifgroup;

	// Usually want to destroy the interface first
	if ($destroyfirst) {

		wg_destroy_if($wg_ifname);

		exec("{$wgquickpath} down {$wg_ifname}" . ($verbose ? "" : " > /dev/null 2>&1"));

	}

	// Bring up interface using wg-quick(8)
	exec("{$wgquickpath} up {$wg_ifname}" . ($verbose ? "" : " > /dev/null 2>&1"));

	// Add the interface to interface group (i.e. WireGuard)
	exec("ifconfig {$wg_ifname} group {$wgifgroup}");

	// Regenerate interface group in pfSense (just in case)
	wg_ifgroup_install();

}


// Remove WireGuard tunnel
function wg_destroy_if($wg_ifname) {
	return (pfSense_interface_destroy($wg_ifname));
}

function deleteTunnel($tunidx) {
	global $config, $wgconfpath;

	if ($config['installedpackages']['wireguard']['tunnel'][$tunidx]) {
		unset($ifname);
		unset($conf_path);
		if (isset($config['installedpackages']['wireguard']['tunnel'][$tunidx]['name'])) {
			$ifname =
			    $config['installedpackages']['wireguard']['tunnel'][$tunidx]['name'];
		}
		if (isset($ifname)) {
			$conf_path = $wgconfpath . "/" . $ifname . ".conf";
		}
		// Delete the tunnel configuration entry
		unset($config['installedpackages']['wireguard']['tunnel'][$tunidx]);
		write_config("WireGuard tunnel {$index} updated.");

		// Delete the wg?.conf file
		if (isset($conf_path) && is_file($conf_path)) {
			unlink($conf_path);
		}

		// Destroy the deleted tunnel
		wg_destroy_if($ifname);
	}
}

function wg_ifgroup_install() {
	global $g, $config, $wgifgroup;

	if (!is_array($config['ifgroups'])) {
		$config['ifgroups'] = array();
	}

	// Create interface group
	if (!is_array($config['ifgroups']['ifgroupentry'])) {
		$config['ifgroups']['ifgroupentry'] = array();
	}

	$a_ifgroups = &$config['ifgroups']['ifgroupentry'];

	// Don't add the interface group if it already exists
	$found = false;
	foreach ($a_ifgroups as $ifg) {
		if ($ifg['ifname'] == $wgifgroup) {
			$found = true;
		}
	}

	if (!$found) {
		$ifgroupentry = array();
		$ifgroupentry['members'] = '';
		$ifgroupentry['descr'] = 'WireGuard (DO NOT REMOVE)';
		$ifgroupentry['hide'] = 'yes';
		$ifgroupentry['ifname'] = $wgifgroup;
		$a_ifgroups[] = $ifgroupentry;
	}

	write_config("WireGuard interface group updated.");

	unlink_if_exists("{$g['tmp_path']}/config.cache");

}


function wg_earlyshellcmd_deinstall() {
	global $config;

	# TODO

}

function wg_earlyshellcmd_install() {
	global $config;

	# TODO

}

function wg_install() {

	wg_earlyshellcmd_install();

	wg_configure();

}

// Write new tunnel values to the configuration system
function wg_do_post($post, $json = false) {
	global $config;

	init_config_arr(array('installedpackages', 'wireguard', 'tunnel'));

	$input_errors = array();

	$index = $post['index'];

	$pconfig = &$config['installedpackages']['wireguard']['tunnel'][$index];

	if (empty($pconfig['name'])) {
		$pconfig['name'] = next_wg_if();
	}
	$pconfig['enabled'] = empty($post['enabled']) ? 'no':'yes';
	$pconfig['descr'] = $post['descr'];

	// Interface section
	$pconfig['interface']['address'] = $post['address'];
	$pconfig['interface']['listenport'] = $post['listenport'];
	$pconfig['interface']['privatekey'] = $post['privatekey'];
	$pconfig['interface']['publickey'] = genPubKey($post['privatekey']);
	
	$pconfig['interface']['mtu'] = $post['mtu'];
	$pconfig['interface']['assigned'] = $post['assigned'];

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
		write_config("WireGuard tunnel {$index} updated.");
	}

	return(array('input_errors' => $input_errors, 'pconfig' => $pconfig));
}

/*
 * Read the WireGuard configurations from config.xml and create a number of
 * *.conf files for wg-quick to read
 */
function wg_resync() {

	wg_configure();

}

function wg_create_config_files($clean = true) {
	global $config, $wgconfpath;

	if ($config['installedpackages']['wireguard']['tunnel']) {
		$wg_tunnels = $config['installedpackages']['wireguard']['tunnel'];
		$cfgpath = $wgconfpath;

		if (!file_exists($cfgpath)) {
			mkdir($cfgpath, 0700, true);
		} else {
			chmod($cfgpath, 0700);
		}

		if ($clean) {
			delete_wg_configs();
		}

		foreach ($wg_tunnels as $tunnel) {
			if (!empty($tunnel['enabled']) &&
			    $tunnel['enabled'] == 'yes') {
				make_wg_conf($tunnel);
			}
		}
	}
}

// Write each file
function make_wg_conf($tunnel) {
	global $wgconfpath;

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

	# We want to handle routes manually
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

	file_put_contents($wgconfpath . "/" . $tunnel['name'] . ".conf", $txt);

	chmod($wgconfpath . "/" . $tunnel['name'] . ".conf", 0600);
}

// Remove all wg config files from the conf directory
function delete_wg_configs() {
	global $wgconfpath;

	unlink_if_exists($wgconfpath . "/*.conf");

}

/* Check if at least one tunnel is enabled */
function is_wg_enabled() {
	global $config;

	init_config_arr(array('installedpackages', 'wireguard', 'tunnel'));

	foreach ($config['installedpackages']['wireguard']['tunnel'] as $tunnel) {
		if (empty($tunnel['enabled'])) {
			continue;
		}
		return true;
	}

	return false;
}

/* Return WireGuard tunnel networks for a given address family */
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

/* Locate a viable remote gateway address for a WireGuard tunnel
 * Fall back to using the tunnel address itself.
 * https://redmine.pfsense.org/issues/11300 */
function wg_find_tunnel_gw($tunnel, $addr) {
	list($ip, $mask) = explode("/", trim($addr));
	/* Loop through peers looking for a viable remote gateway address */
	if (is_array($tunnel['peers']) &&
	    is_array($tunnel['peers']['wgpeer']) &&
	    count($tunnel['peers']['wgpeer']) > 0) {
		foreach ($tunnel['peers']['wgpeer'] as $peer) {
			/* If this peer has no configured Peer WireGuard Address, skip it. */
			if (empty($peer['peerwgaddr'])) {
				continue;
			}
			/* Check each Peer WireGuard Address entry */
			foreach (explode(',', $peer['peerwgaddr']) as $pwga) {
				/* Ensure the address family of this entry matches the one we're seeking */
				if (is_v4($ip) !== is_v4($pwga)) {
					continue;
				}
				/* If there is a subnet mask, ditch it. */
				list($pip, $pmask) = explode('/', trim($pwga));
				/* Check that this address is in the desired subnet */
				if (ip_in_subnet($pip, trim($addr))) {
					/* We found a good candidate, return it */
					return $pip;
				}
			}
		}
	}
	/* If no viable candidate is found, return the tunnel address */
	return $ip;
}