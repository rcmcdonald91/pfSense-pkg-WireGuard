<?php
/*
 * wg_install.inc
 *
 * part of pfSense (https://www.pfsense.org)
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
require_once('config.inc');
require_once('globals.inc');

// WireGuard includes
require_once('wireguard/wg_globals.inc');

/*
 * This is the main install hook
 */
function wg_install() {
	global $g;

	$g['wireguard_installing'] = true;

	update_status("\n  Creating WireGuard interface group...");

	// Installs the 'WireGuard' interface group
	wg_ifgroup_install();

	update_status(" done.\n");

	update_status("  Upgrading XML structure as necessary...");

	wg_upgrade_addresses();

	wg_upgrade_allowedips();

	update_status(" done.\n");

	// The first organic resync called by pfSense package manager will finish the installation process

}

function wg_upgrade_allowedips() {
	global $wgg;

	// Read latest settings
	wg_globals();

	// Save a copy for manipulation
	$peers = $wgg['peers'];

	foreach ($peers as $p_index => $peer) {

		if (!is_array($wgg['peers'][$p_index]['allowedips'])) {

			unset($wgg['peers'][$p_index]['allowedips']);

			$a_allowedips = explode(',', $peer['allowedips']);

			$tmp_addrs = array();

			foreach($a_allowedips as $a_index => $ip) {

				$tmp_addrs['item'][$a_index]['addr'] = $ip;

				$tmp_addrs['item'][$a_index]['descr'] = null;

				$tmp_addrs['item'][$a_index]['peeraddr'] = null;

			}

			$wgg['peers'][$p_index]['allowedips'] = $tmp_addrs;

		}

	}

	// Write the changes out to disk
	write_config("[WireGuard] Upgraded peer allowed ips XML structure.");

	// Read latest settings
	wg_globals();

	// Save a copy for manipulation
	$peers = $wgg['peers'];

	foreach ($peers as $p_index => $peer) {

		if (!is_array($wgg['peers'][$p_index]['allowedips']['row'])) {

			unset($wgg['peers'][$p_index]['allowedips']);

			$tmp_addrs = array();

			foreach ($peer['allowedips']['item'] as $a_index => $item) {

				list($addr, $addr_mask) = explode('/', $item['addr']);

				$tmp_addrs['row'][$a_index]['address'] = $addr;

				$tmp_addrs['row'][$a_index]['mask'] = $addr_mask;

				$tmp_addrs['row'][$a_index]['description'] = $item['descr'];

			}

			$wgg['peers'][$p_index]['allowedips'] = $tmp_addrs;

		}

	}
	
	// Write the changes out to disk
	write_config("[WireGuard] Upgraded peer allowed ips XML structure.");

}

function wg_upgrade_addidtags() {
	global $wgg;

	// Read latest settings
	wg_globals();

	foreach ($wgg['tunnels'] as $t_index => $tunnel) {

		if (is_array($tunnel) && !isset($tunnel['tunid']) {

			$wgg['tunnels'][$t_index]['tunid'] = $t_index;

		}

	}

	// Write the changes out to disk
	write_config("[WireGuard] Upgraded tunnel id tag XML structure.");

	wg_globals();

	foreach ($wgg['peers'] as $p_index => $peer) {

		if (is_array($peer) && !isset($peer['peerid'])) {

			$wgg['peers'][$p_index]['peerid'] = $p_index;

		}

	}

	// Write the changes out to disk
	write_config("[WireGuard] Upgraded peer id tag XML structure.");

}

function wg_upgrade_addresses() {
	global $wgg;

	// Read latest settings
	wg_globals();

	// Save a copy for manipulation
	$tunnels = $wgg['tunnels'];

	foreach ($tunnels as $t_index => $tunnel) {

		if (!is_array($wgg['tunnels'][$t_index]['addresses'])) {

			unset($wgg['tunnels'][$t_index]['addresses']);

			$a_addresses = explode(',', $tunnel['addresses']);

			$tmp_addrs = array();

			foreach($a_addresses as $a_index=> $address) {

				$tmp_addrs['item'][$a_index]['addr'] = $address;

				$tmp_addrs['item'][$a_index]['descr'] = null;

			}

			$wgg['tunnels'][$t_index]['addresses'] = $tmp_addrs;

		}
	

	}

	// Write the changes out to disk
	write_config("[WireGuard] Upgraded tunnel addresses XML structure.");

	// Read latest settings
	wg_globals();

	// Save a copy for manipulation
	$tunnels = $wgg['tunnels'];

	foreach ($tunnels as $t_index => $tunnel) {

		if (!is_array($wgg['tunnels'][$t_index]['addresses']['row'])) {

			unset($wgg['tunnels'][$t_index]['addresses']);

			$tmp_addrs = array();

			foreach ($tunnel['addresses']['item'] as $a_index => $item) {

				list($addr, $addr_mask) = explode('/', $item['addr']);

				$tmp_addrs['row'][$a_index]['address'] = $addr;

				$tmp_addrs['row'][$a_index]['mask'] = $addr_mask;

				$tmp_addrs['row'][$a_index]['description'] = $item['descr'];

			}

			$wgg['tunnels'][$t_index]['addresses'] = $tmp_addrs;

		}

	}

	// Write the changes out to disk
	write_config("[WireGuard] Upgraded tunnel addresses XML structure.");

}

/*
 * This is the main deinstall hook
 */
function wg_deinstall() {
	global $config, $wgg;

	wg_globals();

	update_status("  Removing WireGuard interface group... ");

	wg_ifgroup_deinstall();

	update_status("done.\n  Removing WireGuard temporary files... ");

	wg_delete_config_files();

	update_status("done.\n");

	if (isset($wgg['config']['keep_conf']) && $wgg['config']['keep_conf'] == 'yes') {

		update_status("  Keeping WireGuard configuration settings... ");

		update_status("done.\n");

	} else {

		update_status("  Removing WireGuard configuration settings... ");

		wg_remove_config_settings();

		update_status("done.\n");

	}

}

/*
 * This function creates the WireGuard interface group
 */
function wg_ifgroup_install() {
	global $g, $config, $wgg;

	wg_ifgroup_deinstall();

	init_config_arr(array('ifgroups', 'ifgroupentry'));

	$a_ifgroups = &$config['ifgroups']['ifgroupentry'];

	$a_ifgroups[] = $wgg['ifgroupentry'];

	write_config("[WireGuard] Interface group ({$wgg['ifgroupentry']['ifname']}) (re)installed.");

}

/*
 * This function removes the WireGuard interface group
 */
function wg_ifgroup_deinstall() {
	global $g, $config, $wgg;

	init_config_arr(array('ifgroups', 'ifgroupentry'));

	$a_ifgroups = &$config['ifgroups']['ifgroupentry'];

	foreach ($a_ifgroups as $index => $ifg) {

		if ($ifg['ifname'] == $wgg['ifgroupentry']['ifname']) {

			unset($a_ifgroups[$index]);

		}
		
	}

	write_config("[WireGuard] Interface group ({$wgg['ifgroupentry']['ifname']}) de-installed.");

}