<?php

global $priv_list;

$priv_list['page-vpn-wireguard'] = array();
$priv_list['page-vpn-wireguard']['name'] = "WebCfg - VPN: WireGuard";
$priv_list['page-vpn-wireguard']['descr'] = "Allow access to the 'VPN: WireGuard' page.";
$priv_list['page-vpn-wireguard']['match'] = array();

$priv_list['page-vpn-wireguard']['match'][] = "wg/vpn_wg.php";
$priv_list['page-vpn-wireguard']['match'][] = "wg/vpn_wg_edit.php";

$priv_list['page-status-wireguard'] = array();
$priv_list['page-status-wireguard']['name'] = "WebCfg - Status: WireGuard Status";
$priv_list['page-status-wireguard']['descr'] = "Allow access to the 'Status: WireGuard Status' page.";
$priv_list['page-status-wireguard']['match'] = array();

$priv_list['page-status-wireguard']['match'][] = "wg/status_wireguard.php";

?>
