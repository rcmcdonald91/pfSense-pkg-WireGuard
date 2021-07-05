<?php
/*
 * wireguard.widget.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/theonemcdonald)
 * Copyright (c) 2021 Vajonam
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

// pfSense includes
require_once('guiconfig.inc');
require_once('util.inc');

// WireGuard includes
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_guiconfig.inc');
require_once('wireguard/includes/wg_service.inc');

// Widget includes
require_once('/usr/local/www/widgets/include/wireguard.inc');

// On user settings save, update preferences
if ($_POST && !isset($_REQUEST['ajax'])) {

	if (isset($_POST["refresh_interval"]) && is_numeric($_POST["refresh_interval"]) && ($_POST["refresh_interval"] >= 1) && ($_POST["refresh_interval"] <= 10)) {

		$user_settings["widgets"]["wireguard"]["refresh_interval"] = $_POST["refresh_interval"];

	}

	save_widget_settings($_SESSION['Username'], $user_settings["widgets"], gettext("Updated WireGuard widget settings via dashboard."));
	header("Location: /");
	exit(0);

}

// Default the refresh interval to every update cycle
if (isset($user_settings['widgets']['wireguard']['refresh_interval'])) {

	$wireguard_refresh_interval = (int)$user_settings['widgets']['wireguard']['refresh_interval'];

} else {

	$wireguard_refresh_interval = 1;

}

global $wgg;

wg_globals();

// For the wideget we only want the number of active peers
$a_devices = wg_get_status(true);

if (empty($wgg['tunnels'])):

print_info_box(gettext('No WireGuard tunnels have been configured.'), 'warning', null);

elseif (empty($a_devices)):

print_info_box(gettext('No WireGuard status information is available.'), 'warning', null);

else:

?>
<div class="table-responsive panel-body" id="wireguard_status">
	<table class="table table-hover table-striped table-condensed" style="overflow-x: visible;">
		<thead>
			<th><?=gettext('Tunnel')?></th>
			<th><?=gettext('Description')?></th>
			<th><?=gettext('Active Peers')?></th>
			<th><?=gettext('Listen Port')?></th>
			<th><?=gettext('RX')?></th>
			<th><?=gettext('TX')?></th>
		</thead>
		<tbody>
<?php
foreach ($a_devices as $device_name => $device):
?>
			<tr class="tunnel-entry">
				<td>
					<?=wg_interface_status_icon($device['status'])?>
					<a href="wg/vpn_wg_tunnels_edit.php?tun=<?=htmlspecialchars($device_name)?>"><?=htmlspecialchars($device_name)?>
				</td>
				<td><?=htmlspecialchars(wg_truncate_pretty($device['config']['descr'], 16))?></td>
				<td><?=count($device['peers'])?></td>
				<td><?=htmlspecialchars($device['listen_port'])?></td>
				<td><?=htmlspecialchars(format_bytes($device['transfer_rx']))?></td>
				<td><?=htmlspecialchars(format_bytes($device['transfer_tx']))?></td>
			</tr>
<?php
endforeach;
?>
		</tbody>
	</table>
</div>

<?php

/* for AJAX response, we only need the panels */
if ($_REQUEST['ajax']) {
	exit;
}

?>

<!-- close the body we're wrapped in and add a configuration-panel -->
</div>

<div id="widget-<?=$widgetname?>_panel-footer" class="panel-footer collapse">

	<form action="/widgets/widgets/wireguard.widget.php" method="post" class="form-horizontal">
		<div class="form-group">
			<label for="wireguard-interval" class="col-sm-3 control-label"><?=gettext('Refresh Interval')?></label>
			<div class="col-sm-9">
				<input type="number" id="refresh_interval" name="refresh_interval" value="<?=htmlspecialchars($wireguard_refresh_interval)?>" min="1" max="10" class="form-control" />
			</div>
		</div>

		<div class="form-group">
			<div class="col-sm-offset-3 col-sm-6">
				<button type="submit" class="btn btn-primary"><i class="fa fa-save icon-embed-btn"></i><?=gettext('Save')?></button>
			</div>
		</div>
	</form>

<script type="text/javascript">
//<![CDATA[

	events.push(function(){

		// Callback function called by refresh system when data is retrieved
		function wireguard_callback(s) {
			$('#wireguard_status').html(s);
		}

		// POST data to send via AJAX
		var postdata = {
			ajax: "ajax"
		};

		// Create an object defining the widget refresh AJAX call
		var wireguardObject = new Object();
		wireguardObject.name = "wireguard";
		wireguardObject.url = "/widgets/widgets/wireguard.widget.php";
		wireguardObject.callback = wireguard_callback;
		wireguardObject.parms = postdata;
		wireguardObject.freq = <?=json_encode($wireguard_refresh_interval)?>;

		// Register the AJAX object
		register_ajax(wireguardObject);

	});

//]]>
</script>
<?php
endif;
?>
