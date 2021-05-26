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

	ignore_user_abort(true);

	set_time_limit(0);

	if (!wg_is_cli()) {

		// Bail out if we aren't in the CLI...
		die("FATAL: This script can only be started through the CLI.\n");

	}

	if (PHP_BINARY != $wgg['php_wg']) {

		// Bail out if we aren't running under under the correct executable...
		die("FATAL: This script can only be executed by {$wgg['php_wg']}.\n");

	}

	switch (strtolower($argv[1])) {
		
		case 'start':

		case 'coldstart':
	
			// We want to perform a cold start
			$ret_code = wg_service_cli_start(true);
	
			exit($ret_code);

		case 'warmstart':

			// We want to perform a warm start
			$ret_code = wg_service_cli_start(false);

			exit($ret_code);

		case 'stop':
	
			$ret_code = wg_service_cli_stop();
	
			exit($ret_code);

		default:

			// We shouldn't be here...
			exit(1);

	}

}

function wg_is_cli() {

	return (PHP_SAPI == 'cli');

}

// This is a wrapper for safely calling from web frontend
function wg_service_restart() {

	if (wg_is_service_running()) {

		wg_service_stop();

	}

	$resync_ret = wg_resync_all();

	// Only bring up the service if the resync was successful
	if ($resync_ret['ret_code'] == 0) {

		// Warm start (cold_start = false) because we've already built the tunnels
		wg_service_start(false);

	}

	return $resync_ret;

}

// This is a wrapper for safely calling from web frontend
function wg_service_stop() {
	global $wgg;

	$ret_code = mwexec("{$wgg['wg_daemon']} stop");

	return $ret_code;

}

function wg_service_cli_stop() {
	global $wgg;

	if (!wg_is_cli()) {

		return 1;

	}

	$ret_code = killbypid($wgg['pid_path']);
	
	return $ret_code;

}

function wg_is_service_running() {
	global $wgg;

	if (!($h_lock = @fopen($wgg['pid_path'], 'r')) || !file_exists($wgg['pid_path'])) {

		return false;

	}

	$not_running = flock($h_lock, LOCK_EX | LOCK_NB, $wouldblock);

	if ($not_running) {
	
		flock($h_lock, LOCK_UN);

	}

	$pid = fgets($h_lock);

	// Another trick to test if a process is running
	$sig_test = posix_kill($pid, 0);

	fclose($h_lock);

	return (!$not_running || $wouldblock || $sig_test);

}

// This is a wrapper for safely calling from web frontend
function wg_service_start($cold_start = true) {
	global $wgg;

	$start_type = $cold_start ? 'coldstart' : 'warmstart';

	$ret_code = mwexec("{$wgg['wg_daemon']} {$start_type}");

	return $ret_code;

}

/*
 * does everything, useful for system startup and starting the service at the command line
 */
function wg_service_cli_start($cold_start = true) {
	global $g, $wgg;

	if (!wg_is_cli()) {
		
		// Service invocation error
		return 1;

	}

	if (wg_is_service_running() || is_subsystem_dirty('wireguard_firststart')){

		clear_subsystem_dirty('wireguard_firststart');

		// Service invocation error
		return 1;

	}

	// Set the process name
	cli_set_process_title('WireGuard service');

	// Register the service environment and lock early to ensure singletons
	wg_register_service_env(false);

	// A cold start means we are building tunnels and then starting the daemon
	if ($cold_start) {

		if (platform_booting()) {

			// This absolutely needs to be a file on disk to remain accessible between process instances
			mark_subsystem_dirty('wireguard_firststart');

			print_message("Configuring WireGuard tunnels...");

			// Supresses ifconfig spew 
			mute_kernel_msgs();

		}
	
		// Build the tunnels
		$resync_ret = wg_resync_all();
 
		if (platform_booting()) {

			unmute_kernel_msgs();

			print_message("done. \n");

			// Returns the aggregated return code bit shifted to include the full return code
			return (($resync_ret['ret_code'] << 1) | ($resync_ret['retcode'] <> 0));

		}

		// Should we proceeed with forking?
		if ($resync_ret['ret_code'] <> 0) {

			foreach ($resync_ret['tunnels'] as $tunnel) {

				foreach ($tunnel['errors'] as $error_text) {
		
					print_message("[{$tunnel['name']}] {$error_text}\n");
		
				}
		
			}

			// Service invocation error + resync return code bitshifted by 1
			return (($resync_ret['ret_code'] << 1) | ($resync_ret['retcode'] <> 0));

		}

	}

	// Now, the initial fork...
	$newpid = pcntl_fork();

	if ($newpid === -1) {

		wg_destroy_tunnels();

		// Service invocation error
		return 1;

	} elseif ($newpid) {

		// Returns the aggregated return code bit shifted to include the full return code
		return ($cold_start ? (($resync_ret['ret_code'] << 1) | ($resync_ret['retcode'] <> 0)) : 0);

	}

	// Now become the session leader
	if (posix_setsid() < 0) {

		wg_destroy_tunnels();

		// Service invocation error
		return 1;

	}

	// The second fork...
	$newpid = pcntl_fork();

	if ($newpid === -1) {

		wg_destroy_tunnels();

		// Service invocation error
		return 1;

	} elseif ($newpid) {

		// Make sure to reap the child...
		pcntl_waitpid($newpid, $status);

		// Move on to the daemon
		wg_service_daemon();

	} else {

		// dpinger
		setup_gateways_monitor();

		// unbound
		services_unbound_configure();

		// pf
		filter_configure();

		// This is a best effort at this point...
		return 0;

	}

	// We shouldn't be here...
	return 1;

}

function wg_service_daemon() {
	global $wgg;

	// Re-register the service environment and obtain a fresh lock now that we have finished restarting additional services
	wg_register_service_env(true);

	// Now that we are properly daemonized, register the service signal handlers
	wg_register_daemon_sig_handler();

	// Attempt to load the kmod, required to run the service without any tunnels configured
	if (!is_module_loaded($wgg['kmod'])) {

		$kmod = $wgg['kmod'];

		wg_escapeshellarg($kmod);

		mwexec("{$wgg['kldload']} {$kmod}");

	}

	// Main daemon loop
	while (true) {

		// Check if any new signals are waiting for dispatch
		pcntl_signal_dispatch();

		// The whole point of this daemon...
		if (!is_module_loaded($wgg['kmod'])) {

			break;

		}

		// Wait a bit before trying again
		sleep(1);

	}

	// Send a signal to self to terminate gracefully
	posix_kill(getmypid(), SIGTERM);

	// Fall though just in case
	return 0;

}

function wg_service_install() {
	global $wgg;

	wg_service_deinstall();

	link($wgg['php'], $wgg['php_wg']);

}

function wg_service_deinstall() {
	global $wgg;

	stop_service('wireguard');

	unlink_if_exists($wgg['php_wg']);

}

function wg_service_rcfile() {
	global $wgg;

	$start = $stop = array();

	$start[] = "{$wgg['wg_daemon']} coldstart";

	$stop[] = "{$wgg['wg_daemon']} stop";

	$rcfile['file'] 	= 'wireguardd';

	$rcfile['start'] 	= implode("\n\t", $start);

	$rcfile['stop'] 	= implode("\n\t", $stop);

	write_rcfile($rcfile);

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

function wg_register_service_env($close_handlers = false) {
	global $h_lock, $wgg;

	wg_deregister_service_env();

	$h_lock = fopen($wgg['pid_path'], 'a+');

	flock($h_lock, LOCK_EX);

	ftruncate($h_lock, 0);

	fseek($h_lock, 0, 0);

	fwrite($h_lock, getmypid());

	fflush($h_lock);

	if ($close_handlers) {

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

			// Cleanup the service environment
			wg_deregister_service_env();

			// Teardown tunnels and unload the module
			wg_destroy_tunnels();

			// We are done...
			exit(0);

			break;

		default:

			break;

	}

}

// This is a hack to get text onto the console during booting
function print_message($message) {

	$message = gettext($message);

    	wg_escapeshellarg($message);

	mwexec("printf {$message} >&2");

}

?>