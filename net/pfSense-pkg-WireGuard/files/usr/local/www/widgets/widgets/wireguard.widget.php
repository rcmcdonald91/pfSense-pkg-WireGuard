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

global $wgg;

wg_globals();

$a_devices = wg_get_status();

if (empty($wgg['tunnels'])):

print_info_box(gettext('No WireGuard tunnels have been configured.'), 'warning', null);

elseif (empty($a_devices)):

print_info_box(gettext('No WireGuard status information is available.'), 'warning', null);

else:

?>
<div class="table-responsive panel-body">
	<table class="table table-hover table-striped table-condensed" style="overflow-x: visible;">
		<thead>
			<th><?=gettext('Tunnel')?></th>
			<th><?=gettext('Description')?></th>
			<th><?=gettext('# Peers')?></th>
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
endif;
?>
