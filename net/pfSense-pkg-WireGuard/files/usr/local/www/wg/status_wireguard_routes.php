<?php
/*
 * status_wireguard_routes.php
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
require_once('util.inc');

// WireGuard includes
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_guiconfig.inc');

global $wgg;

wg_globals();

// This is the main entry into the post switchboard for this page.
['is_apply' => $is_apply, 'ret_code' => $ret_code] = wg_status_post_handler($_POST);

$s = fn($x) => $x;

$shortcut_section = 'wireguard';

$pgtitle = array(gettext('Status'), gettext('WireGuard'), gettext('Routes'));
$pglinks = array('', '/wg/status_wireguard.php', '@self');

$tab_array = array();
$tab_array[] = array(gettext('Overview'), false, '/wg/status_wireguard.php');
$tab_array[] = array(gettext('Routes'), true, '/wg/status_wireguard_routes.php');
$tab_array[] = array(gettext('Package'), false, '/wg/status_wireguard_package.php');

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
		<h2 class="panel-title"><?=gettext("IPv4 Routes")?></h2>
	</div>
	<div class="table-responsive panel-body">
		<table class="table table-hover table-striped table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<th><?=gettext('Destination')?></th>
				<th><?=gettext('Interface')?></th>
				<th><?=gettext('Description')?></th>
				<th><?=gettext('Gateway')?></th>
				<th><?=gettext('Flags')?></th>
				<th><?=gettext('Use')?></th>
				<th><?=gettext('MTU')?></th>
			</thead>
			<tbody id="v4routes">
				<tr>
					<td colspan="7">
						<?=print_info_box("<i class=\"fa fa-gear fa-spin\"></i>&nbsp;&nbsp;{$s(gettext('Collecting WireGuard route information.'))}", 'warning', null)?>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext("IPv6 Routes")?></h2>
	</div>
	<div class="table-responsive panel-body">
		<table class="table table-hover table-striped table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<th><?=gettext('Destination')?></th>
				<th><?=gettext('Interface')?></th>
				<th><?=gettext('Description')?></th>
				<th><?=gettext('Gateway')?></th>
				<th><?=gettext('Flags')?></th>
				<th><?=gettext('Use')?></th>
				<th><?=gettext('MTU')?></th>
			</thead>
			<tbody id="v6routes">
				<tr>
					<td colspan="7">
						<?=print_info_box("<i class=\"fa fa-gear fa-spin\"></i>&nbsp;&nbsp;{$s(gettext('Collecting WireGuard route information.'))}", 'warning', null)?>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
</div>

<?php wg_print_configuration_hint(); ?>

<script type="text/javascript">
//<![CDATA[
events.push(function(){

	function updateRoutes(family, section) {

		ajaxRequest = $.ajax(
			{
				url: '/wg/status_wireguard_routes.php',
				type: 'post',
				data: {
					act: 'getroutes',
					family: family
				},
			success: function(response, textStatus, jqXHR) {
				$(section).html(response);
			}
		});

	}

	function updateAllRoutes() {
		updateRoutes('inet', '#v4routes');
		updateRoutes('inet6', '#v6routes');
	}

	setInterval(function() {

		updateAllRoutes();

	}, 5000);

	updateAllRoutes();

});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>