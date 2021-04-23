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

$pgtitle = array(gettext("Status"), "WireGuard");
$pglinks = array("", "@self");

$tab_array = array();
$tab_array[] = array(gettext("Tunnels"), false, "/wg/vpn_wg.php");
$tab_array[] = array(gettext("Settings"), false, "/wg/vpn_wg_settings.php");
$tab_array[] = array(gettext("Status"), true, "/wg/status_wireguard.php");

include("head.inc");

if (!is_module_loaded($wgg['kmod'])) {

	print_info_box(gettext("The WireGuard kernel module is not loaded!"), 'danger');

}

display_top_tabs($tab_array);

?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title">Connection Status</h2>
	</div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<pre><?=wg_status(); ?></pre>
		</dl>
    </div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title">Interface Status</h2>
	</div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<pre><?=wg_interface_status(); ?></pre>
		</dl>
    </div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title">Package Versions</h2>
	</div>
	<div class="table-responsive panel-body">
		<table class="table table-hover table-striped table-condensed">
			<thead>
				<tr>
					<th>Name</th>
					<th>Version</th>
    					<th>Comment</th>
				</tr>
			</thead>
			<tbody>
<?php

			$a_packages = wg_pkg_info();

			foreach ($a_packages as $package):

?>
    				<tr>
        				<td><?=$package[0]?></td>
    					<td><?=$package[1]?></td>
					<td><?=$package[2]?></td>

				</tr>
<?php
			endforeach;
?>

			</tbody>
		</table>
	</div>
</div>

<?php include("foot.inc"); ?>
