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

foreach ($a_devices as $device_name => $device):

?>
			<thead>
				<th><?=gettext("Interface")?></th>
				<th colspan="1"><?=gettext("Public Key")?></th>
				<th colspan="6"><?=gettext("Listen Port")?></th>
			</thead>
			<tbody>	
				<tr>
					<td><?=htmlspecialchars($device_name)?></td>
					<td colspan="1"><?=htmlspecialchars(wg_truncate_pretty($device['public_key'], 16))?></td>
					<td colspan="6"><?=htmlspecialchars($device['listen_port'])?></td>
				<tr>
			</tbody>	
			<thead>
				<th><?=gettext("Peer")?></th>
				<th><?=gettext("Public Key")?></th>
				<th><?=gettext("Endpoint")?></th>
				<th><?=gettext("Allowed IPs")?></th>
				<th><?=gettext("Latest Handshake")?></th>
				<th><?=gettext("RX")?></th>
				<th><?=gettext("TX")?></th>
			</thead>
			<tbody>
<?php
	foreach($device['peers'] as $peer):
?>
				<tr>
					<td><?=htmlspecialchars(wg_truncate_pretty($peer['name'], 16))?></td>
					<td><?=htmlspecialchars(wg_truncate_pretty($peer['public_key'], 16))?></td>
					<td><?=htmlspecialchars($peer['endpoint'])?></td>
					<td><?=htmlspecialchars($peer['allowed_ips'])?></td>
					<td>
						<i class="<?=wg_handshake_status_icon($peer['latest_handshake'])?>"></i>
						<?=htmlspecialchars($peer['latest_handshake_human'])?>
					</td>
					<td><?=htmlspecialchars($peer['transfer_tx_human'])?></td>
					<td><?=htmlspecialchars($peer['transfer_rx_human'])?></td>
				</tr>
			</tbody>
<?php	
	endforeach;
endforeach;
?>
		</table>

		<div style="float: right;"> 
			<p style="display: table-cell;"><i class="fa fa-handshake text-success" style="vertical-align: middle">&nbsp;</i><?=gettext('Less than 5 minutes')?>&nbsp;
			<i class="fa fa-handshake text-warning" style="vertical-align: middle">&nbsp;</i><?=gettext('Less than 6 hours')?>&nbsp;
			<i class="fa fa-handshake text-danger" style="vertical-align: middle">&nbsp;</i><?=gettext('More than 6 hours')?></p>
		</div>


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