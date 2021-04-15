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

init_config_arr(array('installedpackages', 'wireguard', 'config', 0));
$wg_config = &$config['installedpackages']['wireguard']['config'][0];

$pconfig['keep_conf'] = isset($wg_config['keep_conf']) ? $wg_config['keep_conf'] : 'yes';

if ($_POST) {

	if ($_POST['save']) {

		if (!$input_errors) {

			$pconfig = $_POST;

			$wg_config['keep_conf'] = $pconfig['keep_conf'];

			$wg_config['keep_extras'] = $pconfig['keep_extras'];
			
			$wg_config['blur_secrets'] = $pconfig['blur_secrets'];

			write_config('[WireGuard] Save WireGuard settings');

			//wg_resync();

			header("Location: /wg/vpn_wg_settings.php");

		}

	}

}

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

$section = new Form_Section("General Settings");

$section->addInput(new Form_Checkbox(
	'keep_conf',
	'Keep Configuration',
    	gettext('Enable'),
    	$wg_config['keep_conf'] == 'yes'
))->setHelp('<span class="text-danger">Note: </span>'
		. 'With \'Keep Configurations\' enabled (default), all tunnel configurations and package settings will persist on install/de-install.'
);

$keep_extras_btn = new Form_Checkbox(
	'keep_extras',
	'Keep Extra Scripts',
    	gettext('Enable'),
    	$wg_config['keep_extras'] == 'yes'
);

// Check if any WireGuard tunnel is assigned to an interface
if (is_wg_assigned()) {

	// Prevent removal of extra scripts 
	$keep_extras_btn->setDisabled();
	$keep_extras_btn->setHelp('<span class="text-danger">Note: </span>'
					. 'Extra scripts <b>cannot be removed</b> with any tunnels assigned to interfaces.';

} else {

	$keep_extras_btn->setHelp('<span class="text-danger">Note: </span>'
				. 'With \'Keep Extra Scripts\' enabled, any extra scripts installed by the package will persist on install/de-install.';

}

$section->addInput($keep_extras_btn);

$form->add($section);

$section = new Form_Section("User Interface Settings");

$section->addInput(new Form_Checkbox(
	'blur_secrets',
	'Blur Secrets',
    	gettext('Enable'),
    	$wg_config['blur_secrets'] == 'yes'
))->setHelp('<span class="text-danger">Note: </span>'
		. 'With \'Blur Secrets\' enabled, all secrets (private and pre-shared keys) are blurred in the user interface.'
);

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

});
//]]>
</script>

<?php

include("foot.inc");

?>