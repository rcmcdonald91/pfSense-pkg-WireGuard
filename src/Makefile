# $FreeBSD$

PORTNAME=	pfSense-pkg-WireGuard
PORTVERSION=	0.0.4
PORREVISION=	0
CATEGORIES=	net
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty


MAINTAINER=	rcmcdonald91@gmail.com
COMMENT=	pfSense package WireGuard

LICENSE=	APACHE20

RUN_DEPENDS=	${LOCALBASE}/bin/bash:shells/bash \
		wg:net/wireguard-tools \
		wg-quick:net/wireguard-tools \
		${KMODDIR}/if_wg.ko:net/wireguard-kmod

NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}/etc/inc/priv

	${MKDIR} ${STAGEDIR}${PREFIX}/etc

	${MKDIR} ${STAGEDIR}${PREFIX}/pkg
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/wireguard
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/wireguard/etc

	${MKDIR} ${STAGEDIR}${PREFIX}/www
	${MKDIR} ${STAGEDIR}${PREFIX}/www/shortcuts
	${MKDIR} ${STAGEDIR}${PREFIX}/www/wg

	${MKDIR} ${STAGEDIR}${DATADIR}
	
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/wireguard.priv.inc \
		${STAGEDIR}/etc/inc/priv

	${INSTALL_DATA} -m 0755 ${FILESDIR}${PREFIX}/etc/rc.reload_wireguard \
		${STAGEDIR}${PREFIX}/etc

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/wireguard.xml \
		${STAGEDIR}${PREFIX}/pkg

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/wireguard/wg.inc \
		${STAGEDIR}${PREFIX}/pkg/wireguard
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/wireguard/wg_api.inc \
		${STAGEDIR}${PREFIX}/pkg/wireguard
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/wireguard/wg_extras.inc \
		${STAGEDIR}${PREFIX}/pkg/wireguard
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/wireguard/wg_validate.inc \
		${STAGEDIR}${PREFIX}/pkg/wireguard
	${INSTALL_DATA} -m 0755 ${FILESDIR}${PREFIX}/pkg/wireguard/etc/rc.bootstrap_wireguard \
		${STAGEDIR}${PREFIX}/pkg/wireguard/etc

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/shortcuts/pkg_wireguard.inc \
		${STAGEDIR}${PREFIX}/www/shortcuts

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wg/status_wireguard.php \
		${STAGEDIR}${PREFIX}/www/wg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wg/vpn_wg.php \
		${STAGEDIR}${PREFIX}/www/wg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wg/vpn_wg_edit.php \
		${STAGEDIR}${PREFIX}/www/wg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wg/vpn_wg_settings.php \
		${STAGEDIR}${PREFIX}/www/wg
		
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}

	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml \
		${STAGEDIR}${PREFIX}/pkg/wireguard.xml

.include <bsd.port.mk>
