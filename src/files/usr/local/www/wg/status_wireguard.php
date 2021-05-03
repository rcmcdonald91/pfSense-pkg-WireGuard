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

$a_devices = wg_status();

if (!empty($a_devices)):

?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('WireGuard Status')?></h2>
	</div>
	<div class="table-responsive panel-body">
		<table class="table table-hover table-striped table-condensed" style="overflow-x: 'visible'"> 
<?php

	foreach ($a_devices as $device_name => $device):

?>
			<thead>
				<th><?=gettext("Interface")?></th>
				<th colspan="1"><?=gettext("Public Key")?></th>
				<th colspan="6"><?=gettext("Listen Port")?></th>
			</thead>
			<tbody>	
				<tr>
					<td>
						<a href="vpn_wg_tunnels_edit.php?tun=<?=$device_name?>"><?=htmlspecialchars($device_name)?>
					</td>
					<td colspan="1"><?=htmlspecialchars(wg_truncate_pretty($device['public_key'], 16))?></td>
					<td colspan="6"><?=htmlspecialchars($device['listen_port'])?></td>
				<tr>
			</tbody>	
			<thead>
				<th><?=gettext("Peer")?></th>
				<th><?=gettext("Public Key")?></th>
				<th><?=gettext("Endpoint : Port")?></th>
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
					<td>
						<?=htmlspecialchars(wg_truncate_pretty($peer['descr'], 16))?>
					</td>
					<td><?=htmlspecialchars(wg_truncate_pretty($peer['public_key'], 16))?></td>
					<td><?=htmlspecialchars($peer['endpoint'])?></td>
					<td><?=wg_generate_addresses_popup_link($peer['allowed_ips_array'], 'Allowed IPs', "vpn_wg_peers_edit.php?peer={$peer['id']}")?></td>
					<td>
						<?=wg_handshake_status_icon($peer['latest_handshake'])?>
						<?=htmlspecialchars(wg_human_time_diff($peer['latest_handshake']))?>
					</td>
					<td><?=htmlspecialchars(format_bytes($peer['transfer_tx']))?></td>
					<td><?=htmlspecialchars(format_bytes($peer['transfer_rx']))?></td>
				</tr>
			</tbody>
<?php	
		endforeach;
	endforeach;
?>
		</table>



    	</div>


</div>

<div class="panel panel-default ">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Interface Status')?>
	</div>
	
	<div class="table-responsive panel-body">
		<table class="table table-hover table-striped table-condensed" style="overflow-x: 'visible'"> 
	<thead>
				<th><?=gettext("Interface")?></th>
				<th><?=gettext("IPs")?></th>
				<th><?=gettext("MTU")?></th>
				<th><?=gettext("Flags")?></th>
				<th><?=gettext("Description")?></th>
			</thead>
			<tbody>
<?php

$a_intefaces = wg_interface_status();

foreach ($a_intefaces as $key => $a_interface):
?>
				<tr>
					<td><?=htmlspecialchars(($a_interface['interface']))?></td>
					<td><?=wg_generate_addresses_popup_link($a_interface['ips'],gettext("IPs"),"vpn_wg_tunnels_edit.php?tun=${a_interface['interface']}")?></td>
					<td><?=htmlspecialchars(($a_interface['mtu']))?></td>
					<td><?=htmlspecialchars(($a_interface['flags']))?></td>
					<td><?=htmlspecialchars(($a_interface['descr']))?></td>
				<tr>
<?
endforeach;
?>
			</tbody>	
		</table>
    </div>
</div>


<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Routes Status')?>
			<span class="widget-heading-icon">
				<a data-toggle="collapse" href="#wg_routes_status">
					<!--  actual icon is determined in css based on state of body -->
					<i class="fa fa-plus-circle"></i>
				</a>
			</span>
		</h2>
	</div>

	<div id="wg_routes_status" class="table-responsive panel-body collapse" aria-expanded="false">

			<div id="IPv4_parent" class="panel-heading"><h2 class="panel-title"><?=gettext("IPv4")?></h2></div>
				<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" id="IPv4">
				<thead>
					<tr>
						<th><!-- filled by xhr --></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><?=gettext("Gathering data, please wait...")?></td>
					</tr>
				</tbody>
				</table>
		
			<div id="IPv6_parent" class="panel-heading"><h2 class="panel-title"><?=gettext("IPv6")?></h2></div>
				<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" id="IPv6">
				<thead>
					<tr>
						<th><!-- filled by xhr --></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><?=gettext("Gathering data, please wait...")?></td>
					</tr>
				</tbody>
				</table>
	</div>

</div>

<?php
else:

	print_info_box("No WireGuard tunnels have been configured.", 'warning', null);

endif;
?>


<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Package Versions')?>
		<span class="widget-heading-icon">
				<a data-toggle="collapse" href="#panel_package_status">
					<!--  actual icon is determined in css based on state of body -->
					<i class="fa fa-plus-circle"></i>
				</a>
			</span>
		</h2>
		</h2>
	</div>

	<div id="panel_package_status" class="table-responsive panel-body collapse" aria-expanded="false">
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

<script type="text/javascript">
//<![CDATA[
function update_routes(section) {
	$.ajax(
		'/diag_routes.php',
		{
			type: 'post',
			data: 'isAjax=true&filter=<?=$wgg['if_prefix']?>' +'&'+ section +'=true',
			success: update_routes_callback,
	});
}

function update_routes_callback(html) {
	// First line contains section
	var responseTextArr = html.split("\n");
	var section = responseTextArr.shift();
	var tbody = '';
	var field = '';
	var tr_class = '';
	var thead = '<tr>';
	var columns  = 0;

	for (var i = 0; i < responseTextArr.length; i++) {

		if (responseTextArr[i] == "") {
			continue;
		}

		if (i == 0) {
			var tmp = '';
		} else {
			var tmp = '<tr>';
		}

		var j = 0;
		var entry = responseTextArr[i].split(" ");
		columns = entry.length;
		for (var k = 0; k < entry.length; k++) {
			if (entry[k] == "") {
				continue;
			}
			if (i == 0) {
				tmp += '<th>' + entry[k] + '<\/th>';
			} else {
				tmp += '<td>' + entry[k] + '<\/td>';
			}
			j++;
		}

		if (i == 0) {
			thead += tmp;
		} else {
			tmp += '<td><\/td>'
			tbody += tmp;
		}
	}

	// if no routes found  ignore the sections and remove them the dom
	if (tbody == "") {
		$('#' + section + ' > thead').remove();
		$('#' + section + ' > tbody').remove();
		$('#' + section + '_parent').remove();
	} else {
		$('#' + section + ' > thead').html(thead);
		$('#' + section + ' > tbody').html(tbody);
	}
}

function update_all_routes() {
	update_routes("IPv4");
	update_routes("IPv6");
}

events.push(function() {
	setInterval('update_all_routes()', 30000);
	update_all_routes();

});
//]]>
</script>

<?php 

include('foot.inc');

include('wireguard/wg_foot.inc');

?>