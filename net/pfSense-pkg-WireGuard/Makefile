PORTNAME=	pfSense-pkg-WireGuard
PORTVERSION=	0.1.5
PORTREVISION=	1
CATEGORIES=	net
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	coreteam@pfsense.org
COMMENT=	pfSense package WireGuard (EXPERIMENTAL)

LICENSE=	APACHE20

RUN_DEPENDS=	wireguard-kmod>0:net/wireguard-kmod \
		wireguard-tools-lite>0:net/wireguard-tools@lite

BUILD_DEPENDS=	php74-composer2>0:devel/php-composer2

NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

PKG_ROOT=	/pkg/wireguard

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}/etc/inc/priv

	${MKDIR} ${STAGEDIR}${PREFIX}${PKG_ROOT}/classes
	${MKDIR} ${STAGEDIR}${PREFIX}${PKG_ROOT}/includes
	${MKDIR} ${STAGEDIR}${PREFIX}${PKG_ROOT}/vendor

	${MKDIR} ${STAGEDIR}${PREFIX}/www/shortcuts
	${MKDIR} ${STAGEDIR}${PREFIX}/www/widgets/include
	${MKDIR} ${STAGEDIR}${PREFIX}/www/widgets/widgets
	${MKDIR} ${STAGEDIR}${PREFIX}/www/wg/js

	${MKDIR} ${STAGEDIR}${DATADIR}

	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/*.priv.inc \
		${STAGEDIR}/etc/inc/priv

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/*.xml \
		${STAGEDIR}${PREFIX}/pkg

	${INSTALL_DATA} ${FILESDIR}${PREFIX}${PKG_ROOT}/classes/*.class.php \
		${STAGEDIR}${PREFIX}${PKG_ROOT}/classes

	${INSTALL_DATA} ${FILESDIR}${PREFIX}${PKG_ROOT}/includes/*.inc \
		${STAGEDIR}${PREFIX}${PKG_ROOT}/includes

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/shortcuts/*.inc \
		${STAGEDIR}${PREFIX}/www/shortcuts

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/widgets/include/*.inc \
		${STAGEDIR}${PREFIX}/www/widgets/include

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/widgets/widgets/*.widget.php \
		${STAGEDIR}${PREFIX}/www/widgets/widgets

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wg/*.php \
		${STAGEDIR}${PREFIX}/www/wg

	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/wg/js/*.js \
		${STAGEDIR}${PREFIX}/www/wg/js

	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}

	(composer install --no-interaction --no-progress)

	(cd ${FILESDIR}${PREFIX}${PKG_ROOT}/vendor \
		&& ${COPYTREE_SHARE} . ${STAGEDIR}${PREFIX}${PKG_ROOT}/vendor)

	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml \
		${STAGEDIR}${PREFIX}/pkg/wireguard.xml

pre-clean:
	@${RM} -r ${FILESDIR}${PREFIX}${PKG_ROOT}/vendor

.include <bsd.port.mk>
