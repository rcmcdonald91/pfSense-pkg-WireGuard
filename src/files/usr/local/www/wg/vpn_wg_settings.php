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

require_once("guiconfig.inc");
require_once("functions.inc");

$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("Settings"));
$pglinks = array("", "vpn_wg.php", "@self");
$shortcut_section = "wireguard";

$tab_array = array();
$tab_array[] = array(gettext("Tunnels"), false, "vpn_wg.php");
$tab_array[] = array(gettext("Settings"), true, "vpn_wg_settings.php");
$tab_array[] = array(gettext("Status"), false, "status_wireguard.php");

include("head.inc");

add_package_tabs("wireguard", $tab_array);

display_top_tabs($tab_array);

include("foot.inc");

?>