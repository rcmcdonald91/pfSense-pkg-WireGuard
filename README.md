# pfSense-pkg-WireGuard
This is the official WireGuard package for pfSense CE and pfSense Plus.

The package includes tons improvments and new features such as a proper status page and improved assigned interface handling.

Because of the present limitations with pfSense internals and what packages can (and cannot) do on the system, this package includes several opinionated design changes that attempt to work around these limitations. The goal of this package is to use nothing more than what pfSense gives us and to leave the base project intact and not modified. This greatly accelerates the review and testing required for consideration in the offical package collection.

These changes include: 
1. XML configuration bits have been moved from `wireguard/tunnel` to `installedpackages/wireguard/tunnel` (this package will NOT convert tunnels created using the old 2.5.0 schema and config location). You will need to recreate these configurations.
3. Assigned interfaces are now configured under the traditional pfSense `interfaces.php` page. Unassigned tunnels are still configured through the WireGuard UI.
4. Gateways are no longer automatically created for tunnels assigned to pfSense interfaces. Just like any other WAN, you will now be required to create your own gateway entries for the tunnel remote side if you intended to route traffic over the tunnel itself.
5. There is now a proper status page at Status > WireGuard Status. This page includes various bits from `wg(8)`, `ifconfig(8)`, `pkg(7)`, and `kldstat(8)`. 

## Build
The build process is similar to that of other FreeBSD and pfSense packages. You will need to set up a FreeBSD build environment and install or build `wireguard` and `wireguard-kmod` on it. Please check the [pfSense package development documentation](https://docs.netgate.com/pfsense/en/latest/development/developing-packages.html#testing-building-individual-packages) for more information.

`wireguard-kmod` requires headers found in the kernel source and expects these header files to be found at `SRC_BASE=/usr/src`. 

## Installation
Install the latest version via the [pfSense Package Manager.](https://docs.netgate.com/pfsense/en/latest/packages/index.html)

## Configuration

https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/index.html

## Recognition

\*** This project is sponsored by [Rubicon Communications LLC (d.b.a Netgate)](https:/www.netgate.com/)

\*** "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
