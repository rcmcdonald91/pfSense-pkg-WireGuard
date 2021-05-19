# pfSense-pkg-WireGuard
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->
This is a port of the original WireGuard*** UI bits as implemented by [Netgate](https://www.netgate.com/) in [pfSense 2.5.0](https://github.com/pfsense/pfsense/tree/RELENG_2_5_0) to a package suitable for sideloading and more frequent updating on future releases of pfSense.

This also includes some improvments such as a proper status page (found under Status / WireGuard Status) and improved assigned interface handling.

Because of the present limitations with pfSense internals and what packages can (and cannot) do on the system, this package includes several opinionated design changes that attempt to work around these limitations. The goal of this package is to use nothing more than what pfSense gives us and to leave the core codebase untouched. This will (should) greatly accelerate the review and testing required for consideration in the offical package repository.

These changes include: 
1. XML configuration bits have been moved from `wireguard/tunnel` to `installedpackages/wireguard/tunnel` (this package will currently NOT convert tunnels created using the old 2.5.0 schema and config location).
3. Assigned interfaces are now configured under the traditional pfSense `interfaces.php` page. Unassigned tunnels are still configured through the WireGuard UI.
4. Gateways are no longer automatically created for tunnels assigned to pfSense interfaces. Just like any other WAN, you will now be required to create your own gateway entries for the tunnel remote side if you intended to route traffic over the tunnel itself.
5. There is now a proper status page at Status > WireGuard Status. This page includes various bits from `wg(8)`, `ifconfig(8)`, `pkg(7)`, and `kldstat(8)`. 

Note: I have now moved development to the dev branch. Moving forward main will contain code that has been tested. If you want to run dev branch code, you will need to checkout the branch and `make package` yourself.

**Developed on pfSense 2.6.0-DEVELOPMENT snapshots.**

**Now tested on pfSense 2.5.1 and 2.6.0-DEVELOPMENT**

**DO NOT INSTALL ON pfSense 2.5.0.** 

## Build
The build process is similar to that of other FreeBSD and pfSense packages. You will need to set up a FreeBSD build environment and install or build `wireguard` and `wireguard-kmod` on it. Please check the [pfSense package development documentation](https://docs.netgate.com/pfsense/en/latest/development/developing-packages.html#testing-building-individual-packages) for more information.

`wireguard-kmod` requires headers found in the kernel source and header files in `SRC_BASE=/usr/src` . Here is one solution:

for 12.2-RELEASE , amd64
```bash
cd /tmp
fetch ftp://ftp.freebsd.org/pub/FreeBSD/releases/amd64/12.2-RELEASE/src.txz
tar -C / -zxvf src.txz
rm /tmp/src.txz
```

## Installation
This package depends on the `wireguard-tools` and `wireguard-kmod` ports for FreeBSD. Download or build these packages for that version of FreeBSD, then manually install them using `pkg` before installing this package.

Look for latest package links of `wireguard-tools` and `wireguard-kmod` in [FreeBSD 12 repository](https://pkg.freebsd.org/FreeBSD:12:amd64/latest/All/). 

NOTE: As of **4/6/2021**, `wireguard-kmod` is not being actively built by FreshPorts. You will probably have to build these packages manually.

You can find pre-compiled binaries and packages [here](https://github.com/theonemcdonald/pfSense-pkg-WireGuard/releases).

## Configuration

https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/index.html

## Recognition

\*** "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/theonemcdonald"><img src="https://avatars.githubusercontent.com/u/3102039?v=4?s=100" width="100px;" alt=""/><br /><sub><b>R. Christian McDonald</b></sub></a><br /><a href="#projectManagement-theonemcdonald" title="Project Management">📆</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!