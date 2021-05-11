<?php
/*
 * wg_service.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/theonemcdonald)
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
require_once('gwlb.inc');
require_once('util.inc');
require_once('services.inc');
require_once('service-utils.inc');

// WireGuard includes
require_once('wireguard/wg.inc');

if (isset($argv[1])) {

	if ($argv[1] == 'wg_service_start') {

		ignore_user_abort(true);

		set_time_limit(0);

		wg_service_start();

		wg_service_daemon();

		exit;

	} elseif ($argv[1] == 'wg_service_stop') {

		ignore_user_abort(true);

		set_time_limit(0);

		wg_service_stop();

		exit;

	} else {

		exit;

	}

}

function wg_service_stop() {
	global $wgg;

	wg_destroy_tunnels();

	killbyname(basename($wgg['wg_daemon']));

	return;

}

function wg_service_start() {
	global $g, $wgg;

	if (platform_booting()) {

		$g['wireguard_firststart'] = true;

		print_message("Configuring WireGuard tunnels...");

		mute_kernel_msgs();

	}

	wg_create_config_files();

	foreach ($wgg['tunnels'] as $tunnel) {
	
		wg_resync_tunnel($tunnel['name'], true);
	
	}
 
	if (platform_booting()) {

		unmute_kernel_msgs();

		print_message("done. \n");

		// Let the boot process continue and handle additional service and package invocation
		return;

	}

	if ($g['wireguard_firststart']) {

		unset($g['wireguard_firststart']);

		return;

	}

	setup_gateways_monitor();

	services_unbound_configure();

	return;

}

function wg_service_daemon() {
	global $wgg;

	if (!platform_booting() || !is_process_running(basename($wgg['wg_daemon']))) {

		while (TRUE) {

			if (!is_module_loaded($wgg['kmod'])) {

				break;

			}

			sleep(1);

		}

	}

	return;

}

function wg_service_install() {
	global $wgg;

	stop_service('wireguard');

	unlink_if_exists($wgg['wg_daemon']);

	link($wgg['php'], $wgg['wg_daemon']);

}

function wg_service_deinstall() {
	global $wgg;

	stop_service('wireguard');

	unlink_if_exists($wgg['wg_daemon']);

}

function wg_service_rcfile() {
	global $wgg;

	// Remove the included rc from wireguard-tools(8)
	unlink_if_exists("/usr/local/etc/rc.d/wireguard");

	$start = $stop = array();

	$start[] = "{$wgg['wg_daemon']} -f {$wgg['wg_includes']}/wg_service.inc wg_service_start &";

	$stop[] = "{$wgg['wg_daemon']} -f {$wgg['wg_includes']}/wg_service.inc wg_service_stop &";

	$rcfile['file'] 	= 'wireguard.sh';

	$rcfile['start'] 	= implode("\n\t", $start);

	$rcfile['stop'] 	= implode("\n\t", $stop);

	write_rcfile($rcfile);

}

// This is a hack to get text onto the console during booting
function print_message($message) {

	$message = gettext($message);

    	$message = escapeshellarg($message);

	mwexec("printf {$message} >&2");

}

?>