<?php

/*
 * vpn_wg_peers_edit.php
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
##|*MATCH=vpn_wg_peers_edit.php*
##|-PRIV

// pfSense includes
require_once('functions.inc');
require_once('guiconfig.inc');

// WireGuard includes
require_once('wireguard/wg.inc');

global $wgg;

wg_globals();

if (is_numericint($_REQUEST['id'] && is_numericint($_REQUEST['peer']))) {

	$tun_index = $_REQUEST['id'];

	$peer_index = $_REQEST['peer'];

}

$shortcut_section = "wireguard";

$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("Tunnels"), "TUNNEL", "PEER");
$pglinks = array("", "/wg/vpn_wg_tunnels.php", "/wg/vpn_wg_tunnels.php", "/wg/vpn_wg_tunnels_edit.php?id={$i}", "@self");

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

$section = new Form_Section("Peer Configuration (PEER)");

$section->addInput(new Form_Input(
	'peer_num',
	'',
	'hidden'
));

$section->addInput(new Form_Input(
	'pdescr',
	'Description',
	'text'
))->setHelp("Peer description");

$section->addInput(new Form_Input(
	'endpoint',
	'Endpoint',
	'text'
))->setHelp('Hostname, IPv4, or IPv6 address of this peer.%1$s ' .
		'Leave blank if unknown (dynamic endpoints).', '<br />');

$section->addInput(new Form_Input(
	'port',
	'Endpoint Port',
	'text'
))->setHelp('Port used by this peer. Ignored for dynamic endpoints. Leave blank for default (51820).');

$section->addInput(new Form_Input(
	'persistentkeepalive',
	'Keep Alive',
	'text'
))->setHelp('Interval (in seconds) for Keep Alive packets sent to this peer. ' .
		'Default is empty (disabled).', '<br />');

$section->addInput(new Form_Input(
	'ppublickey',
	'*Public Key',
	'text'
))->setHelp('WireGuard Public Key for this peer.');

$section->addInput(new Form_Input(
	'allowedips',
	'Allowed IPs',
	'text'
))->setHelp('List of CIDR-masked IPv4 and IPv6 subnets reached via this peer.%1$s ' .
		'Routes for these subnets are automatically added to the routing table, except for default routes.', '<br/>');

$section->addInput(new Form_Input(
	'peerwgaddr',
	'Peer Address',
	'text'
))->setHelp('Peer IPv4/IPv6 tunnel interface addresses (comma separated) since they can differ from Allowed IPs.', '<br/>');

$group = new Form_Group('Pre-shared Key');

$group->add(new Form_Input(
	'presharedkey',
	'Pre-shared Key',
	$secrets_input_type
))->setHelp('Optional Pre-shared Key for this peer.%1$s ' .
		'Mixes symmetric-key cryptography into public-key cryptography for post-quantum resistance.', '<br/>');

$group->add(new Form_Button(
	'genpsk',
	'Generate',
	null,
	'fa-key'
))->addClass('btn-primary btn-xs')->setHelp('New PSK');

$section->add($group);

$form->add($section);

print($form);

?>

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

<?php

include("foot.inc");

?>