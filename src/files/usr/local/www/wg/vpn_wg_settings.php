<?php
/*
 * vpn_wg.php
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
##|*IDENT=page-vpn-wg-settings
##|*NAME=VPN: WireGuard: Settings
##|*DESCR=WireGuard Settings.
##|*MATCH=vpn_wg_settings.php*
##|-PRIV

// pfSense includes
require_once("guiconfig.inc");
require_once("functions.inc");

// WireGuard includes
require_once("/usr/local/pkg/wireguard/wg.inc");

$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("Settings"));
$pglinks = array("", "/wg/vpn_wg.php", "@self");
$shortcut_section = "wireguard";

$tab_array = array();
$tab_array[] = array(gettext("Tunnels"), false, "vpn_wg.php");
$tab_array[] = array(gettext("Settings"), true, "vpn_wg_settings.php");
$tab_array[] = array(gettext("Status"), false, "status_wireguard.php");

include("head.inc");

add_package_tabs("wireguard", $tab_array);

display_top_tabs($tab_array);

if ($input_errors) {
	print_input_errors($input_errors);
}

$form = new Form(false);

$section = new Form_Section("WireGuard Settings");

$section->addInput(new Form_Input(
    'mtu',
    'Default MTU',
    'text',
    $pconfig['mtu'],
    ['placeholder' => wg_default_mtu()]
))->setHelp('This is typically %s bytes but can vary in some circumstances.', wg_default_mtu());

$form->add($section);

print($form);

?>

<nav class="action-buttons">
	<button type="submit" id="saveform" name="saveform" class="btn btn-sm btn-primary" value="save" title="<?=gettext('Save Settings')?>">
		<i class="fa fa-save icon-embed-btn"></i>
		<?=gettext("Save")?>
	</button>
</nav>

<?php $jpconfig = json_encode($pconfig, JSON_HEX_APOS); ?>

<!-- ============== JavaScript =================================================================================================-->
<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var pconfig = JSON.parse('<?=$jpconfig?>');

	// Eliminate ghost lines in modal
	$('.form-group').css({"border-bottom-width" : "0"});

	// Return text from peer table cell
	function tabletext (row, col) {
		row++; col++;
		return $('#peertable tr:nth-child(' + row + ') td:nth-child('+ col + ')').text();
	}


	// Save the form
	$('#saveform').click(function () {

		$('<input>').attr({type: 'hidden',name: 'save',value: 'save'}).appendTo(form);


		$(form).submit();
	});

	// These are action buttons, not submit buttons
	$("#savemodal").prop('type' ,'button');




	// Warn the user if the peer table has been updated, but the form has not yet been saved ----------------------------
	// Save the table state on page load
	var tableHash = hashCode($('#peertable').html());

	window.addEventListener('beforeunload', (event) => {
		// If the table has changed since page load . .
		if (hashCode($('#peertable').html()) !== tableHash) {
			// Cause the browser to display "Are you sure" message)
			// Unfortunately it is no longer possible to customize the browser message
			event.returnValue = '';
		}
	});

	function hashCode(s){
		return s.split("").reduce(function(a,b){a=((a<<5)-a)+b.charCodeAt(0);return a&a},0);
	}
});
//]]>
</script>

<?php

include("foot.inc");

?>