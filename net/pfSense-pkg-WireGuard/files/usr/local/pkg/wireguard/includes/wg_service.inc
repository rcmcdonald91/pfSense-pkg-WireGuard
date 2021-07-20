<?php
/*
 * wg_service.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
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
require_once('wireguard/includes/wg.inc');

global $wgg;

$ret_code = 0;

// This script only makes sense in the context of the CLI...
if (!wg_is_cli()) {

	die("FATAL: This script can only be started through the CLI.\n");

}

// This script should only be executed by the linked/renamed PHP binary...
if (PHP_BINARY != $wgg['php_wg']) {

	die("FATAL: This script can only be executed by {$wgg['php_wg']}.\n");

}

// Now we can proceed...
ignore_user_abort(true);

set_time_limit(0);

pcntl_async_signals(true);

if (($argc > 1) && !empty($argv[1])) {

	// Should we serialize the return output?
	$serialize = (isset($argv[2]) && (strtolower($argv[2]) == 'serialize'));

	switch (strtolower($argv[1])) {
		
		case 'start':

			$ret_code = wg_service_cli_start($serialize);
			
			break;

		case 'stop':
	
			$ret_code = wg_service_cli_stop($serialize);

			break;

		case 'restart':

			$ret_code = wg_service_cli_restart($serialize);

			break;

		default:

			// Something isn't quite right...
			$ret_code = 1;

			wg_print_usage_instructions();

			break;

	}

	exit($ret_code);

} else {

	wg_print_usage_instructions();

	exit($ret_code);

}

function wg_print_usage_instructions() {
	global $wgg;

	foreach (array(
		"Usage:\n",
		"    {$wgg['wg_daemon']} {ACTION} [OPTIONS]\n\n",
		"Actions:\n",
		"    START\tStart the WireGuard service\n",
		"    STOP\tStop the WireGuard service\n",
		"    RESTART\tRestart the WireGuard service\n\n",
		"Options:\n",
		"    SERIALIZE\tSerialize the output\n"
	) as $line) { fwrite(STDOUT, $line); }

}

function wg_service_cli_restart($serialize = true) {
	global $wgg;

	$ret_code = 0;

	if (wg_is_service_running()) {

		$ret_code = wg_service_cli_stop($serialize);

		if ($ret_code <> 0) {

			return $ret_code;

		}

	}

	$ret_code = wg_service_cli_start($serialize);

	return $ret_code;

}

// Only for calling service stop from the CLI
function wg_service_cli_stop($serialize = true) {
	global $wgg;

	$ret_code = 0;

	if (!wg_is_cli()) {

		$ret_code |= WG_ERROR_SVC_STOP;

		return wg_service_parse_errors($ret_code, $serialize);

	}

	// Need to wait here for just a second...
	if (killbypid($wgg['pid_path'], 1) <> 0) {

		$ret_code |= WG_ERROR_SVC_STOP;

		return wg_service_parse_errors($ret_code, $serialize);

	}

	return $ret_code;

}

// Only for calling service start from the CLI
function wg_service_cli_start($serialize = true) {
	global $g, $wgg;

	$s = fn($x) => $x;

	// Set the process name
	cli_set_process_title('WireGuard service');
	
	$ret_code = 0;

	if (!wg_is_service_enabled()) {

		$ret_code |= WG_ERROR_SVC_DISABLED;

		return wg_service_parse_errors($ret_code, $serialize);

	}

	if (wg_is_service_running()) {

		$ret_code |= WG_ERROR_SVC_RUNNING;

		return wg_service_parse_errors($ret_code, $serialize);

	}

	if (!wg_is_cli()) {

		$ret_code |= WG_ERROR_SVC_START;

		return wg_service_parse_errors($ret_code, $serialize);

	}

	// Register the service environment and lock early to ensure singletons
	wg_register_service_env(false);

	if (platform_booting()) {

		// Output during booting must be to STDERR for some reason
		fwrite(STDERR, gettext('Configuring WireGuard tunnels...'));

		// Supresses ifconfig spew 
		mute_kernel_msgs();

	}

	// Get the tunnel interfaces to build
	$ifs_to_build = wg_get_configured_ifs();

	// Now build them...
	$sync_status = wg_tunnel_sync($ifs_to_build, false);

	if ($sync_status['ret_code'] <> 0 ) {

		$ret_code |= WG_ERROR_SVC_CREATE;

	}

	if (platform_booting()) {

		unmute_kernel_msgs();

		fwrite(STDERR, "{$s(gettext('done.'))}\n");

		return $ret_code;

	}

	// Now, the initial fork...
	$newpid = pcntl_fork();

	if ($newpid === -1) {

		$ret_code |= WG_ERROR_SVC_START;

		wg_destroy_tunnels();

		return wg_service_parse_errors($ret_code, $serialize);

	} elseif ($newpid) {

		return wg_service_parse_errors($ret_code, $serialize);

	}

	// Now become the session leader
	if (posix_setsid() < 0) {

		wg_destroy_tunnels();

		return 1;

	}

	// The second fork...
	$newpid = pcntl_fork();

	if ($newpid === -1) {

		wg_destroy_tunnels();

		return 1;

	} elseif ($newpid) {

		// Reap the child process below...
		pcntl_waitpid($newpid, $status);

		// Boilerplate if we want to trap service ret codes and halt...
		$ret_code = pcntl_wexitstatus($status);

		if ($ret_code <> 0) {

			return $ret_code;
		}

		// Move on to the actual daemon
		wg_service_daemon();

		// We shouldn't be here...
		return 0;

	} else {

		// Now we restart any additional services
		$ret_code = wg_restart_extra_services();

		return $ret_code;

	}

	// We shouldn't be here...
	return 1;

}

// Main WireGuard service loop
function wg_service_daemon() {
	global $wgg;

	// Re-register the service environment
	wg_register_service_env(true);

	// Now that we are properly daemonized, register the service signal handlers
	wg_register_daemon_sig_handler();

	// Attempt to load the kmod, required to run the service without any tunnels configured
	wg_kld_loadunload(true);

	// Now we resolve endpoint hostnames here...
	$last_update_time = wg_resolve_endpoints();

	// Main WireGuard service loop
	while (true) {

		// The whole point of this daemon...
		if (!is_module_loaded($wgg['kmod'])) {

			break;

		}
		
		// Check if we should reresolve hostnames
		if (wg_should_reresolve_endpoints($last_update_time)) {

			// Reresolve endpoint hostnames again
			$last_update_time = wg_resolve_endpoints();

		}

		// Keep running state consistent...
		wg_destroy_rogue_tunnels();

		// Wait a bit before trying again
		sleep(1);

	}

	// Execute SIGTERM handler to exit gracefully
	wg_daemon_sig_handler(SIGTERM);

}

function wg_deregister_service_env() {
	global $h_lock, $wgg;

	if (!is_null($h_lock)) {

		// Attempt to release exclusive lock
		@flock($h_lock, LOCK_UN);

		// Attempt to close file handler
		@fclose($h_lock);

	}

	// Attempt to delete PID file
	unlink_if_exists($wgg['pid_path']);

}

function wg_register_service_env($close_fdio = false) {
	global $h_lock, $wgg;

	wg_deregister_service_env();

	if ($h_lock = fopen($wgg['pid_path'], 'a+')) {

		flock($h_lock, LOCK_EX);

		ftruncate($h_lock, 0);

		fseek($h_lock, 0, 0);

		fwrite($h_lock, getmypid());

		fflush($h_lock);

	}

	if ($close_fdio) {

		fclose(STDIN);

		fclose(STDOUT);

		fclose(STDERR);

	}

}

function wg_register_daemon_sig_handler() {

	pcntl_signal(SIGTERM, 'wg_daemon_sig_handler');

}

function wg_daemon_sig_handler($signo) {

	switch ($signo) {

		case SIGTERM:

			// Teardown any tunnels and unload the module
			wg_destroy_tunnels();

			// Cleanup the service environment
			wg_deregister_service_env();

			// We are done...
			exit(0);

			break;

		default:

			break;

	}

}

function wg_service_parse_errors($ret_code, $serialize_output = true, $extras = null) {
	global $wgg;

	$errors = array();

	// Collect any errors
	foreach ($wgg['error_flags']['service'] as $error_mask => $error_text) {

		if (($ret_code & $error_mask) > 0) {

			$errors[$error_mask] = $error_text;

			if (!$serialize_output) {

				// Send each error to STDERR as it is found
				fwrite(STDERR, "{$error_text}\n");

			}

		}

	}

	if ($serialize_output) {

		$res = array('ret_code' => $ret_code, 'errors' => $errors);

		$res = is_array($extras) ? array_merge($res, $extras) : $res;

		$res_serialized = serialize($res);

		fwrite(STDOUT, "{$res_serialized}\n");

	}

	return $ret_code;

}

?>