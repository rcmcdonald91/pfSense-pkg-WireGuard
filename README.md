# pfSense-pkg-WireGuard
This is an attempt to port the original WireGuard UI bits as implemented by [Netgate](https://www.netgate.com/) in [pfSense 2.5.0](https://github.com/pfsense/pfsense/tree/RELENG_2_5_0) to a package suitable for sideloading and more frequent updating on future releases of pfSense.

XML configuration bits have been moved from `wireguard/tunnel` to `installedpackages/wireguard/tunnel`

Note: I'm currently developing directly in the main branch. I know this is bad practice. Please ignore the mess.

**Developed on pfSense 2.6.0-DEVELOPMENT snapshots.**

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
