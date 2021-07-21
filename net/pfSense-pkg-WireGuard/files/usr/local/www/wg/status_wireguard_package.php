<?php
/*
 * status_wireguard_package.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
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

##|+PRIV
##|*IDENT=page-status-wireguard
##|*NAME=Status: WireGuard
##|*DESCR=Allow access to the 'Status: WireGuard' page.
##|*MATCH=status_wireguard.php*
##|-PRIV

// pfSense includes
require_once('guiconfig.inc');

// WireGuard includes
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_guiconfig.inc');

global $wgg;

wg_globals();

// This is the main entry into the post switchboard for this page.
['is_apply' => $is_apply, 'ret_code' => $ret_code] = wg_status_post_handler($_POST);

$s = fn($x) => $x;

$shortcut_section = 'wireguard';

$pgtitle = array(gettext('Status'), gettext('WireGuard'), gettext('Package'));
$pglinks = array('', '/wg/status_wireguard.php', '@self');

$tab_array = array();
$tab_array[] = array(gettext('Overview'), false, '/wg/status_wireguard.php');
$tab_array[] = array(gettext('Routes'), false, '/wg/status_wireguard_routes.php');
$tab_array[] = array(gettext('Package'), true, '/wg/status_wireguard_package.php');

include('head.inc');

wg_print_service_warning();

if ($is_apply) {

	print_apply_result_box($ret_code);

}

wg_print_config_apply_box();

display_top_tabs($tab_array);

?>

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
					<th><?=gettext('Package Source')?></th>
    					<th><?=gettext('Comment')?></th>
				</tr>
			</thead>
			<tbody>
<?php
			foreach (wg_pkg_info() as ['name' => $name, 'version' => $version, 'source' => $source, 'comment' => $comment]):
?>
    				<tr>
					<td><?=htmlspecialchars($name)?></td>
					<td><?=htmlspecialchars($version)?></td>
					<td><?=htmlspecialchars($source)?></td>
					<td><?=htmlspecialchars($comment)?></td>
				</tr>
<?php
			endforeach;
?>

			</tbody>
		</table>
	</div>
</div>

<?php

wg_print_configuration_hint();

include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>