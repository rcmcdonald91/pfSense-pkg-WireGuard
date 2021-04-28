<?php
/*
 * status_wireguard.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 R. Christian McDonald
 * Copyright (c) 2020 Ascrod
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

##|+PRIV
##|*IDENT=page-status-wireguard
##|*NAME=Status: WireGuard
##|*DESCR=Allow access to the 'Status: WireGuard' page.
##|*MATCH=status_wireguard.php*
##|-PRIV

// pfSense includes
require_once('guiconfig.inc');
require_once('functions.inc');
require_once('shortcuts.inc');
require_once('util.inc');

// WireGuard includes
require_once('wireguard/wg.inc');

// Grab the latest info
wg_globals();

global $wgg;

$shortcut_section = "wireguard";

$pgtitle = array(gettext("Status"), gettext("WireGuard"));
$pglinks = array("", "@self");

$tab_array = array();
$tab_array[] = array(gettext("Tunnels"), false, "/wg/vpn_wg_tunnels.php");
$tab_array[] = array(gettext("Peers"), false, "/wg/vpn_wg_peers.php");
$tab_array[] = array(gettext("Settings"), false, "/wg/vpn_wg_settings.php");
$tab_array[] = array(gettext("Status"), true, "/wg/status_wireguard.php");

include("head.inc");

// Check if the kernel module is loaded
if (!is_module_loaded($wgg['kmod'])) {

	// Warn the user if the kernel module is not loaded
	print_info_box(gettext("The WireGuard kernel module is not loaded!"), 'danger', null);

}

display_top_tabs($tab_array);

?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Connection Status')?></h2>
	</div>
	<div class="table-responsive panel-body">
		<table class="table table-hover table-striped table-condensed" style="overflow-x: 'visible'"> 
<?php

$a_devices = wg_status();

foreach ($a_devices as $device):

	if ($device[0] != $last_device):

		$new_device = true;

		$last_device = $device[0];

?>
			<thead>
				<th><?=gettext("Interface")?></th>
				<th colspan="1"><?=gettext("Public Key")?></th>
				<th colspan="6"><?=getext("Listen Port")?></th>
			</thead>
			<tbody>	
				<tr>
					<td><?=htmlspecialchars($device[0])?></td>
					<td colspan="1"><?=htmlspecialchars(substr($device[2], 0, 16)."...")?></td>
					<td colspan="6"><?=htmlspecialchars($device[3])?></td>
				<tr>
			</tbody>	
<?php 
	elseif:
		if ($new_device):
?>
				<tr>
					<th><?=gettext("Peer")?></th>
					<th><?=gettext("Public Key")?></th>
					<th><?=gettext("Endpoint")?></th>
					<th><?=gettext("Allowed IPs")?></th>
					<th><?=gettext("Last HS")?></th>
					<th><?=gettext("RX")?></th>
					<th><?=gettext("TX")?></th>
					<th><?=gettext("KA")?></th>
				</tr>
<?php
			$new_device = false;
		endif;
?>
				<tr>
					<td><?=get_peer_name($device[1])?></td>
					<td><?=substr($device[1], 0, 16)."..."?></td>
					<td><?=htmlspecialchars($device[3])?> </td>
					<td><?=htmlspecialchars($device[4])?></td>
					<td><?=($device[5] > 0 ? humanTiming($device[5]) : "never"); ?></td>
					<td><?=((is_nan($device[6]) || $device[6] == 0) ? "-" : format_bytes($device[6])); ?></td>
					<td><?=((is_nan($device[7]) || $device[7] == 0) ? "-" : format_bytes($device[7])); ?></td>
					<td><?=htmlspecialchars($device[8])?></td>
				</tr>

<?php	
	endif;
endforeach;
?>
		</table>
    	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Interface Status')?></h2>
	</div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<pre><?=htmlspecialchars(wg_interface_status())?></pre>
		</dl>
    </div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Package Versions')?></h2>
	</div>
	<div class="table-responsive panel-body">
		<table class="table table-hover table-striped table-condensed">
			<thead>
				<tr>
					<th><?=gettext('Name')?></th>
					<th><?=gettext('Version')?></th>
    					<th><?=gettext('Comment')?></th>
				</tr>
			</thead>
			<tbody>
<?php

			$a_packages = wg_pkg_info();

			foreach ($a_packages as $package):

?>
    				<tr>
        				<td><?=htmlspecialchars($package[0])?></td>
    					<td><?=htmlspecialchars($package[1])?></td>
					<td><?=htmlspecialchars($package[2])?></td>

				</tr>
<?php
			endforeach;
?>

			</tbody>
		</table>
	</div>
</div>

<?php 
include("foot.inc"); 
?>