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

	update_status("\nInstalling extra scripts... ");

                // Installs any extra scripts
                wg_extra_scripts_install();

	update_status("Finished installing extra scripts.\n"); 
	
	update_status("Setting up earlyshellcmds... ");
	
                // Installs the earlyshellcmds
                wg_earlyshellcmd_install();

	update_status(" done.\nCreating WireGuard interface group... ");

                // Installs the 'WireGuard' interface group
                wg_ifgroup_install();

	update_status(" done.\nConfiguring existing WireGuard interfaces... ");

                // Configure any existing interfaces
                wg_configure();

	update_status(" done.\n");

	unset($g['wireguard_installing']);

}

/*
 * This is the main deinstall hook
 */
function wg_deinstall() {
	global $wgg;

	update_status("Removing earlyshellcmds... ");

	wg_earlyshellcmd_deinstall($wgg['pkg_scripts']);

	update_status(" done.\nRemoving WireGuard interface group... ");

	wg_ifgroup_deinstall();

	update_status(" done.\n");

}

/*
 * This function installs any extra scripts not installed by pkg(7)
 */
function wg_extra_scripts_install($verbose = true) {
	global $wgg;

	foreach ($wgg['extra_scripts'] as $script) {

		$script_name = basename($script);

		$script_source_path = dirname($script);

		if ($verbose) { 
			
			update_status("\nInstalling {$script_name} to {$wgg['script_path']} ... \n"); 
		
		}

		unlink_if_exists("{$wgg['script_path']}/{$script_name}");

		copy("{$script}", "{$wgg['script_path']}/{$script_name}");

		chmod("{$wgg['script_path']}/{$script_name}", 0755);

		if ($verbose) {

			update_status(" done.\n");

		}

	}

}

/*
 * This function removes any extra scripts not installed by pkg(7)
 */
function wg_extra_scripts_deinstall() {
	# TODO
}

/*
 * This function creates earlyshellcmd entries in the config
 */
function wg_earlyshellcmd_install() {
	global $config, $wgg;

        wg_earlyshellcmd_deinstall($wgg['earlyshellcmds']);

        init_config_arr(array('system', 'earlyshellcmd'));

	$a_earlyshellcmds = &$config['system']['earlyshellcmd'];

	$a_earlyshellcmds = array_merge($wgg['earlyshellcmds'], $a_earlyshellcmds);

        $output = implode(',', $wgg['earlyshellcmds']);

	write_config("[WireGuard] Earlyshellcmds ( {$output} ) (re)installed.");

}

/*
 * This function removes earlyshellcmd entries in the config
 */
function wg_earlyshellcmd_deinstall($cmds_to_deinstall) {
	global $config;

        init_config_arr(array('system', 'earlyshellcmd'));

	$a_earlyshellcmds = &$config['system']['earlyshellcmd'];

	$a_earlyshellcmds = array_diff($a_earlyshellcmds, $cmds_to_deinstall);

	$cmds_to_deinstall = implode(',', $cmds_to_deinstall);

	write_config("[WireGuard] ( {$cmds_to_deinstall} ) earlyshellcmds de-installed.");
	
}

 /*
  * This function creates the WireGuard interface group
  */
function wg_ifgroup_install() {
	global $g, $config, $wgg;

	wg_ifgroup_deinstall();

	init_config_arr(array('ifgroups', 'ifgroupentry'));

	$a_ifgroups = &$config['ifgroups']['ifgroupentry'];

	$wg_group_entry = array();

	$wg_group_entry['ifname'] = $wgg['if_group'];
	$wg_group_entry['descr'] = 'Dynamic Group for WireGuard';
	$wg_group_entry['members'] = '';

	$a_ifgroups[] = $wg_group_entry;

	write_config("[WireGuard] Interface group ({$wgg['if_group']}) (re)installed.");

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

		if ($ifg['ifname'] == $wgg['if_group']) {

			unset($a_ifgroups[$index]);

		}
		
	}

	write_config("[WireGuard] Interface group ({$wgg['if_group']}) de-installed.");

	unlink_if_exists("{$g['tmp_path']}/config.cache");

}