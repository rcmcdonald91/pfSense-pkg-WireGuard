<?php

/*
 * vpn_wg_edit.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2021 R. Christian McDonald
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
##|*NAME=VPN: WireGuard: Edit
##|*DESCR=Allow access to the 'VPN: WireGuard' page.
##|*MATCH=vpn_wg_edit.php*
##|-PRIV

// pfSense includes
require_once('functions.inc');
require_once('guiconfig.inc');

// WireGuard includes
require_once('wireguard/wg.inc');

global $wgg;

wg_globals();

$secrets_input_type = (isset($wgg['config']['hide_secrets']) && $wgg['config']['hide_secrets'] =='yes') ? 'password' : 'text';

if (is_numericint($_REQUEST['id'])) {
	$index = $_REQUEST['id'];
}

if ($_REQUEST['ajax']) {
	switch ($_REQUEST['action']) {
		case "genpsk" : { 
			print(genPSK());
			exit;
		}
	}
}

// All form save logic is in /etc/inc/wg.inc
if ($_POST) {

	if ($_POST['save']) {

		if (empty($_POST['listenport'])) {

			$_POST['listenport'] = next_wg_port();

		}

		$res = wg_do_post($_POST);
		
		$input_errors = $res['input_errors'];

		$pconfig = $res['pconfig'];

		if (!$input_errors) {

			// Create the new WG config files
			wg_create_config_files();
			
			// Attempt to reinstall the interface group to keep things clean
			wg_ifgroup_install();

			// Configure the new WG tunnel
			if (isset($pconfig['enabled']) && $pconfig['enabled'] == 'yes') {

				$conf_hard = (!is_wg_tunnel_assigned($tunnel) || !does_interface_exist($tunnel['name']));

				wg_configure_if($pconfig, $conf_hard);

			} else {

				wg_destroy_if($pconfig);

			}

			// Go back to the tunnel table
			header("Location: /wg/vpn_wg.php");

		}

	} elseif ($_POST['action'] == 'genkeys') {

		// Process ajax call requesting new key pair
		print(genKeyPair(true));

		exit;

	} elseif ($_POST['action'] == 'toggle') {

		echo("You want to toggle {$index}");

		exit;

	}

} else {

	if (isset($index)) {

		if (is_array($wgg['tunnels'][$index])) {

			$pconfig = &$wgg['tunnels'][$index];
		}

	} else {

		$pconfig = array();

		$pconfig['name'] = next_wg_if();

	}

	// Save the MTU settings prior to re(saving)
	$pconfig['mtu'] = get_interface_mtu($pconfig['name']);

}

$shortcut_section = "wireguard";

$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("Tunnels"), gettext($pconfig['name']));
$pglinks = array("", "/wg/vpn_wg_tunnels.php", "/wg/vpn_wg_tunnels.php", "@self");

$tab_array = array();
$tab_array[] = array(gettext("Tunnels"), true, "/wg/vpn_wg_tunnels.php");
$tab_array[] = array(gettext("Settings"), false, "/wg/vpn_wg_settings.php");
$tab_array[] = array(gettext("Status"), false, "/wg/status_wireguard.php");

include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}

display_top_tabs($tab_array);

$form = new Form(false);

// ============ Tunnel edit modal ==================================
$section = new Form_Section("Tunnel Configuration ({$pconfig['name']})");

$form->addGlobal(new Form_Input(
	'index',
	'',
	'hidden',
	$index
));

$tun_enable = new Form_Checkbox(
	'enabled',
	'Tunnel Enabled',
	gettext('Enable'),
	$pconfig['enabled'] == 'yes'
);

$tun_enable->setHelp('<span class="text-danger">Note: </span>Tunnel must be <b>enabled</b> in order to be assigned to an interface');	

// Disable the tunnel enabled button if interface is assigned
if (is_wg_tunnel_assigned($pconfig)) {

	$tun_enable->setDisabled();

	$tun_enable->setHelp('<span class="text-danger">Note: </span>Tunnel cannot be <b>disabled</b> when assigned to an interface');

	// We still want to POST this field, make a a hidden field now
	$form->addGlobal(new Form_Input(
		'enabled',
		'',
		'hidden',
		'yes'
	));

}

$section->addInput($tun_enable);

$section->addInput(new Form_Input(
	'descr',
	'Description',
	gettext('Description'),
	$pconfig['descr']
))->setHelp('Tunnel description for administrative reference (not parsed)');

$section->addInput(new Form_Input(
	'listenport',
	'Listen Port',
	'text',
	$pconfig['interface']['listenport'],
	['placeholder' => next_wg_port()]
))->setHelp('Port used by this tunnel to communicate with peers');

$group = new Form_Group('*Interface Keys');

$group->add(new Form_Input(
	'privatekey',
	'Private Key',
	$secrets_input_type,
	$pconfig['interface']['privatekey']
))->setHelp('Private key for this tunnel (Required)');

$group->add(new Form_Input(
	'publickey',
	'Public Key',
	'text',
	$pconfig['interface']['publickey']
))->setHelp('Public key for this tunnel (%sCopy%s)', '<a id="copypubkey" href="#">', '</a>')->setReadonly();

$group->add(new Form_Button(
	'genkeys',
	'Generate',
	null,
	'fa-key'
))->setWidth(1)->addClass('btn-primary btn-xs')->setHelp('New Keys');

$section->add($group);
$form->add($section);

// ============ Interface edit modal ==================================
$section = new Form_Section("Interface Configuration ({$pconfig['name']})");

if (!is_wg_tunnel_assigned($pconfig)) {

	$section->addInput(new Form_StaticText(
		'Assignment',
		"<a href='../../interfaces_assign.php'>Interface Assignments</a>"
	));

	$section->addInput(new Form_StaticText(
		'Firewall Rules',
		"<a href='../../firewall_rules.php?if={$wgg['if_group']}'>WireGuard Interface Group</a>"
	));

	$section->addInput(new Form_Input(
		'address',
		'Address',
		'text',
		$pconfig['interface']['address']
	))->setHelp('Comma separated list of CIDR-masked IPv4 and IPv6 addresses assigned to the tunnel interface');

} else {

	// We want all configured interfaces, including disabled ones
	$iflist = get_configured_interface_list_by_realif(true);
	$ifdescr = get_configured_interface_with_descr(true);
	
	$ifname = $iflist[$pconfig['name']];
	$iffriendly = $ifdescr[$ifname];

	$section->addInput(new Form_StaticText(
		'Assignment',
		"<a href='../../interfaces_assign.php'>{$iffriendly} ({$ifname})</a>"
	));

	$section->addInput(new Form_StaticText(
		'Interface',
		"<a href='../../interfaces.php?if={$ifname}'>Interface Configuration</a>"
	));

	$section->addInput(new Form_StaticText(
		'Firewall Rules',
		"<a href='../../firewall_rules.php?if={$ifname}'>Firewall Configuration</a>"
	));

}

// We still need to keep track of this otherwise wg-quick and pfSense will fight
$form->addGlobal(new Form_Input(
	'mtu',
	'',
	'hidden',
	$pconfig['mtu']
));

$form->add($section);

print($form);

// ============ Peer edit modal ==================================
$section2 = new Form_Section('Peer');

$section2->addInput(new Form_Input(
	'peer_num',
	'',
	'hidden'
));

$section2->addInput(new Form_Input(
	'pdescr',
	'Description',
	'text'
))->setHelp("Peer description");

$section2->addInput(new Form_Input(
	'endpoint',
	'Endpoint',
	'text'
))->setHelp('Hostname, IPv4, or IPv6 address of this peer.%1$s ' .
		'Leave blank if unknown (dynamic endpoints).', '<br />');

$section2->addInput(new Form_Input(
	'port',
	'Endpoint Port',
	'text'
))->setHelp('Port used by this peer. Ignored for dynamic endpoints. Leave blank for default (51820).');

$section2->addInput(new Form_Input(
	'persistentkeepalive',
	'Keep Alive',
	'text'
))->setHelp('Interval (in seconds) for Keep Alive packets sent to this peer. ' .
		'Default is empty (disabled).', '<br />');

$section2->addInput(new Form_Input(
	'ppublickey',
	'*Public Key',
	'text'
))->setHelp('WireGuard Public Key for this peer.');

$section2->addInput(new Form_Input(
	'allowedips',
	'Allowed IPs',
	'text'
))->setHelp('List of CIDR-masked IPv4 and IPv6 subnets reached via this peer.%1$s ' .
		'Routes for these subnets are automatically added to the routing table, except for default routes.', '<br/>');

$section2->addInput(new Form_Input(
	'peerwgaddr',
	'Peer Address',
	'text'
))->setHelp('Peer IPv4/IPv6 tunnel interface addresses (comma separated) since they can differ from Allowed IPs.', '<br/>');

$group2 = new Form_Group('Pre-shared Key');

$group2->add(new Form_Input(
	'presharedkey',
	'Pre-shared Key',
	$secrets_input_type
))->setHelp('Optional Pre-shared Key for this peer.%1$s ' .
		'Mixes symmetric-key cryptography into public-key cryptography for post-quantum resistance.', '<br/>');

$group2->add(new Form_Button(
	'genpsk',
	'Generate',
	null,
	'fa-key'
))->addClass('btn-primary btn-xs')->setHelp('New PSK');

$section2->add($group2);

?>

<!-- Modal -->
<div id="peermodal" class="modal fade" role="dialog" data-keyboard="false" data-backdrop="static">
  <div class="modal-dialog modal-lg">

	<!-- Modal content-->
	<div class="modal-content">
	<div class="modal-body">
		<?=$section2?>

		<nav class="action-buttons">
			<button type="submit" id="closemodal" class="btn btn-sm btn-info" title="<?=gettext('Cancel')?>">
				<?=gettext("Cancel")?>
			</button>

			<button type="submit" id="savemodal" class="btn btn-sm btn-primary" title="<?=gettext('Update peer')?>">
				<?=gettext("Update")?>
			</button>
		</nav>
	</div>
	</div>

  </div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title">Peer Configuration</h2>
	</div>
	<div id="mainarea" class="table-responsive panel-body">
		<table id="peertable" class="table table-hover table-striped table-condensed" style="overflow-x: 'visible'">
			<thead>
				<tr>
					<th><?=gettext("Peer")?></th>
					<th><?=gettext("Description")?></th>
					<th><?=gettext("Endpoint")?></th>
					<th><?=gettext("Port")?></th>
					<th><?=gettext("Public key")?></th>
					<th style="display:none;"><?=gettext("Keepalive")?></th>
					<th style="display:none;"><?=gettext("Allowed IPs")?></th>
					<th style="display:none;"><?=gettext("PSK")?></th>
					<th></th>

				</tr>
			</thead>
			<tbody>
<?php

		if (!empty($pconfig['peers']['wgpeer'])):

			foreach ($pconfig['peers']['wgpeer'] as $peer => $index):

?>
				<tr>
					<td><?=$index?></td>
					<td><?=htmlspecialchars($peer['descr'])?></td>
					<td><?=htmlspecialchars($peer['endpoint'])?></td>
					<td><?=htmlspecialchars($peer['port'])?></td>
					<td><?=htmlspecialchars($peer['publickey'])?></td>
					<td style="cursor: pointer;">
						<a class="fa fa-pencil" href="#" id="editpeer_<?=$index?>"title="<?=gettext("Edit peer"); ?>"></a>
						<a class="fa fa-trash text-danger no-confirm" href="#" id="killpeer_<?=$index?>" title="<?=gettext('Delete peer');?>"></a>
					</td>
				</tr>

<?php
			endforeach;
		endif;
?>
			</tbody>
		</table>
	</div>
</div>

<nav class="action-buttons">
	<button type="submit" id="editpeer_new" class="btn btn-sm btn-success" title="<?=gettext('Add new peer')?>">
		<i class="fa fa-plus icon-embed-btn"></i>
		<?=gettext("Add peer")?>
	</button>

	<button type="submit" id="saveform" name="saveform" class="btn btn-sm btn-primary" value="save" title="<?=gettext('Save tunnel')?>">
		<i class="fa fa-save icon-embed-btn"></i>
		<?=gettext("Save")?>
	</button>
</nav>

<?php $genkeywarning = gettext("Are you sure you want to overwrite keys?"); ?>

<!-- ============== JavaScript =================================================================================================-->
<script type="text/javascript">
//<![CDATA[
events.push(function() {

	$('#copypubkey').click(function () {
		$('#publickey').focus();
		$('#publickey').select();
		document.execCommand("copy");
	});

	// These are action buttons, not submit buttons
	$("#genkeys").prop('type' ,'button');

	// Request a new public/private key pair
	$('#genkeys').click(function(event) {
		if ($('#privatekey').val().length == 0 || confirm("<?=$genkeywarning?>")) {
			ajaxRequest = $.ajax('/wg/vpn_wg_tunnels_edit.php',
				{
				type: 'post',
				data: {
					action: 'genkeys'
				},
				success: function(response, textStatus, jqXHR) {
					resp = JSON.parse(response);
					$('#publickey').val(resp.pubkey);
					$('#privatekey').val(resp.privkey);
				}
			});
		}
	});

});
//]]>
</script>

<?php

include("foot.inc");

?>