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

	pcntl_async_signals(true);

	// Should we serialize the return output?
	$serialize = (isset($argv[2]) && $argv[2] == 'serialize');

	switch (strtolower($argv[1])) {
		
		case 'start':

			$ret_code = wg_service_cli_start($serialize);
	
			exit($ret_code);
			
			break;

		case 'stop':
	
			$ret_code = wg_service_cli_stop($serialize);
	
			exit($ret_code);

			break;

		default:

			exit(1);

			break;

	}

}

function wg_is_cli() {

	return (PHP_SAPI == 'cli');

}

// This is a wrapper for safely calling from web frontend
function wg_service_web_stop() {
	global $wgg;

	$serialized_output = array();

	// Invokes service stop with serialization flag so we can cleanly report back to the web frontend.
	exec("{$wgg['wg_daemon']} stop serialize", $serialized_output, $ret_code);

	$unserialized_output = unserialize($serialized_output[0]);

	return $unserialized_output;

}

// Only for calling service stop from the CLI
function wg_service_cli_stop($serialize_output = true) {
	global $wgg;

	$ret_code = 0;

	$service_stop_error = (!wg_is_cli());

	if ($service_stop_error) {

		$ret_code |= $service_stop_error << 1;

		wg_service_error_handler($ret_code, $serialize_output);

		return $ret_code;

	}

	$ret_code |= killbypid($wgg['pid_path']) << 1;
	
	wg_service_error_handler($ret_code, $serialize_output);

	return $ret_code;

}

function wg_service_web_restart() {
	global $wgg;

	$stop_status = wg_service_web_stop();

	if ($stop_status['ret_code'] <> 0) {

		return $stop_status;

	}

	$start_status = wg_service_web_start();

	return $start_status;

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
	
	fclose($h_lock);

	// Another trick to test if a process is running
	$sig_test = posix_kill($pid, 0);

	return (!$not_running || $wouldblock || $sig_test);

}

// This is a wrapper for safely calling from the web frontend
function wg_service_web_start() {
	global $wgg;

	$serialized_output = array();

	// Invokes service start with serialization flag so we can cleanly report back to the web frontend.
	exec("{$wgg['wg_daemon']} start serialize", $serialized_output, $ret_code);

	$unserialized_output = unserialize($serialized_output[0]);

	return $unserialized_output;

}

function wg_service_error_handler($ret_code, $serialize_output = true, $extras = array()) {
	global $g, $wgg;

	$errors = array();

	foreach ($wgg['error_flags']['service'] as $error_mask => $error_text) {

		if (($ret_code & $error_mask) > 0) {
	
			if ($serialize_output) {

				$errors[$error_mask] = $error_text;

			} else {

				fwrite(STDERR, "{$error_text}\n");

			}

		}

	}

	if ($serialize_output) {

		$output_to_serialize = array_merge(array('ret_code' => $ret_code, 'errors' => $errors), $extras);

		fwrite(STDOUT, serialize($output_to_serialize));

	}

	return $ret_code;

}

// Only for calling service start from the CLI
function wg_service_cli_start($serialize_output = true) {
	global $g, $wgg;

	// Set the process name
	cli_set_process_title('WireGuard service');
	
	$ret_code = 0;

	$service_start_error = (!wg_is_cli() || wg_is_service_running());

	if ($service_start_error) {

		$ret_code |= $service_start_error << 0;

		wg_service_error_handler($ret_code, $serialize_output);

		return $ret_code;

	}

	// Register the service environment and lock early to ensure singletons
	wg_register_service_env(false);

	if (platform_booting()) {

		// This absolutely needs to be a file on disk to remain accessible between process instances
		mark_subsystem_dirty('wireguard_firststart');

		// Output during booting must be STDERR
		fwrite(STDERR, "Configuring WireGuard tunnels...");

		// Supresses ifconfig spew 
		mute_kernel_msgs();

	}

	// Build the tunnels
	$build_all_status = wg_tunnel_build_all();

	$ret_code |= ($build_all_status['ret_code'] <> 0) << 2;

	if (platform_booting()) {

		unmute_kernel_msgs();

		fwrite(STDERR, "done. \n");

		return $ret_code;

	}

	// Now, the initial fork...
	$newpid = pcntl_fork();

	$service_start_error = ($newpid === -1);

	if ($service_start_error) {

		$ret_code |= $service_start_error << 0;

		wg_destroy_tunnels();

		wg_service_error_handler($ret_code, $serialize_output);

		return $ret_code;

	} elseif ($newpid) {

		wg_service_error_handler($ret_code, $serialize_output, array('build_all' => $build_all_status));

		return $ret_code;

	}

	// Now become the session leader
	if (posix_setsid() < 0) {

		wg_destroy_tunnels();

		return 1;

	}

	/*
	 * From this point on, we are completely detached from the calling tty via posix_setsid().
	 * Any further output via STDOUT, STDERRR, etc. is completely invisible.
	 * 
	 * TODO: This is where a true logging facility would be nice to have.
	 */

	// The second fork...
	$newpid = pcntl_fork();

	if ($newpid === -1) {

		wg_destroy_tunnels();

		return 1;

	} elseif ($newpid) {

		// Make sure to reap the child...
		pcntl_waitpid($newpid, $status);

		// Move on to the daemon
		wg_service_daemon();

		// We shouldn't be here...
		return 0;

	} else {

		// We don't need to restart additional services ifw we just finished booting...
		if (is_subsystem_dirty('wireguard_firststart')) {

			clear_subsystem_dirty('wireguard_firststart');

			return 0;

		}

		/*
		 * This is where we can safely restart any additional services
		 * 
		 * TODO: Allow users to specify additional services to restart here.
		 */


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
	return 0;

}

// Main WireGuard service loop
function wg_service_daemon() {
	global $wgg;

	// Re-register the service environment
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

		// The whole point of this daemon...
		if (!is_module_loaded($wgg['kmod'])) {

			break;

		}

		// Wait a bit before trying again
		sleep(1);

	}

	// Execute SIGTERM handler
	wg_daemon_sig_handler(SIGTERM);

}

function wg_service_install() {
	global $wgg;

	link($wgg['php'], $wgg['php_wg']);

}

function wg_service_deinstall() {
	global $wgg;

	wg_service_web_stop();

	unlink_if_exists($wgg['php_wg']);

}

function wg_service_rcfile() {
	global $wgg;

	$start = $stop = array();

	$start[] = "{$wgg['wg_daemon']} start";

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

	if ($h_lock = fopen($wgg['pid_path'], 'a+')) {

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

}

function wg_register_daemon_sig_handler() {

	pcntl_signal(SIGTERM, 'wg_daemon_sig_handler');

}

function wg_daemon_sig_handler($signo) {

	switch ($signo) {

		case SIGTERM:

			// Cleanup the service environment
			wg_deregister_service_env();

			// Teardown any tunnels and unload the module
			wg_destroy_tunnels();

			// We are done...
			exit(0);

			break;

		default:

			break;

	}

}

?>