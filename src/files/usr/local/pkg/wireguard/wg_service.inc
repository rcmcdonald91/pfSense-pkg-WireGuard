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

	if ($argv[1] == 'wg_service_watchdog') {

		ignore_user_abort(TRUE);

		set_time_limit(0);

		wg_service_watchdog();

		exit;

	} elseif ($argv[1] == 'wg_service_stop') {

		wg_destroy_tunnels();

		exit;

	} elseif ($argv[1] == 'wg_service_start') {

		if (platform_booting()) {

			print_message("Configuring WireGuard tunnels...");

			mute_kernel_msgs();

			wg_resync_all();

			unmute_kernel_msgs();

			print_message("done. \n");

			exit;

		}

		update_status("done.\n  Starting WireGuard service...");

		wg_resync_all();

		setup_gateways_monitor();

		services_unbound_configure();

		update_status("done.\n");

		exit;
	
	} else {

		exit;

	}

}

function wg_service_watchdog() {
	global $wgg;

	if (!platform_booting()) {

		while (TRUE) {

			if (!is_module_loaded($wgg['kmod'])) {

				break;

			}

			sleep(1);

		}

	}

	return false;

}

function wg_service_install() {
	global $wgg;

	stop_service('wireguard');

	unlink_if_exists('/usr/local/bin/php_wg');

	link('/usr/local/bin/php', '/usr/local/bin/php_wg');

}

function wg_service_deinstall() {
	global $wgg;

	stop_service('wireguard');

	unlink_if_exists('/usr/local/bin/php_wg');

}

// This is a hack to get text onto the console during booting
function print_message($message) {

	$message = gettext($message);

    	$message = escapeshellarg($message);

	mwexec("printf {$message} >&2");

}

?>