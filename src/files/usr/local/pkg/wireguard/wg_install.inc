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
require_once('wg_globals.inc');

/*
 * This is the main install hook
 */
function wg_install() {
	global $g;

	$g['wireguard_installing'] = true;

	update_status(" done.\nSetting up earlyshellcmds... ");
	
                // Installs the earlyshellcmds
                wg_earlyshellcmd_install();

	update_status(" done.\nCreating WireGuard interface group... ");

                // Installs the 'WireGuard' interface group
                wg_ifgroup_install();

	update_status(" done.\nConfiguring existing WireGuard interfaces... ");

                // Configure hard any existing interfaces
                wg_configure(true);

	update_status(" done.\n");

	unset($g['wireguard_installing']);

}

/*
 * This is the main deinstall hook
 */
function wg_deinstall() {
	global $wgg;

	update_status("Removing earlyshellcmds... ");

	wg_earlyshellcmd_deinstall();

	update_status(" done.\nRemoving WireGuard interface group... ");

	wg_ifgroup_deinstall();

	update_status(" done.\n");

}

function wg_earlyshellcmd_update() {

	wg_earlyshellcmd_install();

}

/*
 * This function creates earlyshellcmd entries in the config
 */
function wg_earlyshellcmd_install() {
	global $config, $wgg;

	wg_earlyshellcmd_deinstall();

        init_config_arr(array('system', 'earlyshellcmd'));

	$a_earlyshellcmds = &$config['system']['earlyshellcmd'];

	$bs_earlyshellcmds = array();

	// Get a list of all assigned interfaces, even those that are disabled
	$if_list = get_configured_interface_list_by_realif(true);

	foreach ($if_list as $realif => $name) {
	
	    	$ifname = escapeshellarg($realif);
	
		// We are looking for wg interfaces
		if (substr($realif, 0, 2) == "wg") {
	
			// Create a temporary lo loopback interface
			$bs_earlyshellcmds[] = "{$wgg['ifconfig']} {$ifname} || {$wgg['ifconfig']} lo create name {$ifname}";
			
			// Now we add it to the 'wg' group so wg-quick can tear it down later
			$bs_earlyshellcmds[] = "{$wgg['ifconfig']} {$ifname} group wg";
	
		}
	
	}
	
	// Push everything else to the bottom of the list
	$a_earlyshellcmds = array_merge($bs_earlyshellcmds, $wgg['earlyshellcmds'], $a_earlyshellcmds);

	write_config("[WireGuard] Earlyshellcmds (re)installed.");

}

/*
 * This function removes earlyshellcmd entries in the config
 */
function wg_earlyshellcmd_deinstall() {
	global $config, $wgg;

        init_config_arr(array('system', 'earlyshellcmd'));

	$a_earlyshellcmds = &$config['system']['earlyshellcmd'];

	// This is dangerous, only for testing
	unset($a_earlyshellcmds);

	write_config("[WireGuard] Earlyshellcmds removed.")
	
}

function wg_ifgroup_update() {

	wg_ifgroup_install();

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

	unlink_if_exists("{$g['tmp_path']}/config.cache");

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

	unlink_if_exists("{$g['tmp_path']}/config.cache");

}