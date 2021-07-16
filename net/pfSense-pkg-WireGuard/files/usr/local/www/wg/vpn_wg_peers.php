<?php
/*
 * vpn_wg_peers.php
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

##|+PRIV
##|*IDENT=page-vpn-wireguard
##|*NAME=VPN: WireGuard
##|*DESCR=Allow access to the 'VPN: WireGuard' page.
##|*MATCH=vpn_wg_peers.php*
##|-PRIV

// pfSense includes
require_once('functions.inc');
require_once('guiconfig.inc');

// WireGuard includes
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_guiconfig.inc');

global $wgg;

wg_globals();

if ($_POST) {

	if (isset($_POST['apply'])) {

		$ret_code = wg_apply_tunnels_common();

	}

	if (isset($_POST['peer'])) {

		$peer_idx = $_POST['peer'];

		switch ($_POST['act']) {

			case 'toggle':

				$res = wg_toggle_peer($peer_idx);

				break;

			case 'delete':
				
				$res = wg_delete_peer($peer_idx);

				break;

			default:
				
				// Shouldn't be here, so bail out.
				header('Location: /wg/vpn_wg_peers.php');

				break;
				
		}

		$input_errors = $res['input_errors'];

		if (empty($input_errors)) {

			if (wg_is_service_running() && $res['changes']) {

				mark_subsystem_dirty($wgg['subsystems']['wg']);

				// Add tunnel to the list to apply
				wg_apply_list_add('tunnels', $res['tuns_to_sync']);

			}

		}

	}

}

$s = fn($x) => $x;

$shortcut_section = 'wireguard';

$pgtitle = array(gettext('VPN'), gettext('WireGuard'), gettext('Peers'));
$pglinks = array('', '/wg/vpn_wg_tunnels.php', '@self');

include('head.inc');

wg_print_service_warning();

if (isset($_POST['apply'])) {

	print_apply_result_box($ret_code);

}

wg_print_config_apply_box();

if (!empty($input_errors)) {

	print_input_errors($input_errors);

}

wg_tab_array_common('peers');

?>

<form name="mainform" method="post">
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('WireGuard Peers')?></h2></div>
		<div class="panel-body table-responsive">
			<table class="table table-hover table-striped table-condensed">
				<thead>
					<tr>
						<th><?=gettext('Description')?></th>
						<th><?=gettext('Public key')?></th>
						<th><?=gettext('Tunnel')?></th>
						<th><?=gettext('Allowed IPs')?></th>
						<th><?=htmlspecialchars(wg_format_endpoint(true))?></th>
						<th><?=gettext('Actions')?></th>
					</tr>
				</thead>
				<tbody>
<?php
if (is_array($wgg['peers']) && count($wgg['peers']) > 0):

		foreach ($wgg['peers'] as $peer_idx => $peer):
?>
					<tr ondblclick="document.location='<?="vpn_wg_peers_edit.php?peer={$peer_idx}"?>';" class="<?=wg_peer_status_class($peer)?>">
						<td><?=htmlspecialchars(wg_truncate_pretty($peer['descr'], 16))?></td>
						<td class="pubkey" title="<?=htmlspecialchars($peer['publickey'])?>">
							<?=htmlspecialchars(wg_truncate_pretty($peer['publickey'], 16))?>
						</td>
						<td><?=htmlspecialchars($peer['tun'])?></td>
						<td><?=wg_generate_peer_allowedips_popup_link($peer_idx)?></td>
						<td><?=htmlspecialchars(wg_format_endpoint(false, $peer))?></td>
						<td style="cursor: pointer;">
							<a class="fa fa-pencil" title="<?=gettext('Edit Peer')?>" href="<?="vpn_wg_peers_edit.php?peer={$peer_idx}"?>"></a>
							<?=wg_generate_toggle_icon_link(($peer['enabled'] == 'yes'), 'peer', "?act=toggle&peer={$peer_idx}")?>
							<a class="fa fa-trash text-danger" title="<?=gettext('Delete Peer')?>" href="<?="?act=delete&peer={$peer_idx}"?>" usepost></a>
						</td>
					</tr>

<?php
		endforeach;

else:
?>
					<tr>
						<td colspan="6">
							<?php print_info_box(gettext('No WireGuard peers have been configured. Click the "Add Peer" button below to create one.'), 'warning', null); ?>
						</td>
					</tr>
<?php
endif;
?>
				</tbody>
			</table>
		</div>
	</div>
	<nav class="action-buttons">
		<a href="vpn_wg_peers_edit.php" class="btn btn-success btn-sm">
			<i class="fa fa-plus icon-embed-btn"></i>
			<?=gettext('Add Peer')?>
		</a>
	</nav>
</form>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	$('.pubkey').click(function () {

		navigator.clipboard.writeText($(this).attr('title'));

	});

});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>