"""Funções utilitárias de coleta SNMP via PySNMP 6.x (async).

Módulo opcional e modular — pode ser desabilitado por profile. Suporta
SNMPv2c (community string) e SNMPv3/USM (usuário + autenticação/privacidade),
selecionados por ``SnmpCredential.version``.
"""

import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# OIDs comuns
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_IF_NUMBER = "1.3.6.1.2.1.2.1.0"


# ---------------------------------------------------------------------------
# Credencial SNMP (v2c ou v3/USM)
# ---------------------------------------------------------------------------

@dataclass
class SnmpCredential:
    """Parâmetros de autenticação SNMP, abstraindo v2c e v3.

    Para v2c basta ``community``. Para v3 preencha ``v3_user`` e (conforme o
    nível desejado) ``v3_auth_key`` / ``v3_priv_key`` com os respectivos
    protocolos. O nível de segurança é inferido da presença das chaves.
    """
    version: str = "2c"          # "2c" ou "3"
    community: str = "public"
    v3_user: str = ""
    v3_auth_protocol: str = "SHA"
    v3_auth_key: str = ""
    v3_priv_protocol: str = "AES"
    v3_priv_key: str = ""

    @property
    def is_v3(self) -> bool:
        return str(self.version).strip() in ("3", "v3")


def credential_from_profile(profile) -> SnmpCredential:
    """Constrói uma ``SnmpCredential`` a partir de um ``Profile``.

    Lê as propriedades já decifradas do modelo. Sem profile → v2c/public.
    """
    if profile is None:
        return SnmpCredential()
    if str(getattr(profile, "snmp_version", "2c")).strip() in ("3", "v3"):
        return SnmpCredential(
            version="3",
            v3_user=profile.snmp_v3_user or "",
            v3_auth_protocol=(profile.snmp_v3_auth_protocol or "SHA"),
            v3_auth_key=profile.snmp_v3_auth_key or "",
            v3_priv_protocol=(profile.snmp_v3_priv_protocol or "AES"),
            v3_priv_key=profile.snmp_v3_priv_key or "",
        )
    return SnmpCredential(version="2c", community=profile.snmp_community or "public")


# Mapas de protocolo → constante do pysnmp. Resolvidos preguiçosamente para
# não exigir o pysnmp no import do módulo (mantém-no opcional).
_AUTH_PROTO_NAMES = {
    "": "usmNoAuthProtocol",
    "NONE": "usmNoAuthProtocol",
    "MD5": "usmHMACMD5AuthProtocol",
    "SHA": "usmHMACSHAAuthProtocol",
    "SHA1": "usmHMACSHAAuthProtocol",
    "SHA224": "usmHMAC128SHA224AuthProtocol",
    "SHA256": "usmHMAC192SHA256AuthProtocol",
    "SHA384": "usmHMAC256SHA384AuthProtocol",
    "SHA512": "usmHMAC384SHA512AuthProtocol",
}
_PRIV_PROTO_NAMES = {
    "": "usmNoPrivProtocol",
    "NONE": "usmNoPrivProtocol",
    "DES": "usmDESPrivProtocol",
    "3DES": "usm3DESEDEPrivProtocol",
    "AES": "usmAesCfb128Protocol",
    "AES128": "usmAesCfb128Protocol",
    "AES192": "usmAesCfb192Protocol",
    "AES256": "usmAesCfb256Protocol",
}


def _build_auth_data(cred: SnmpCredential):
    """Traduz uma SnmpCredential no objeto de autenticação do pysnmp.

    Retorna ``CommunityData`` (v2c) ou ``UsmUserData`` (v3). Levanta
    ImportError se o pysnmp não estiver instalado (tratado pelo chamador).
    """
    import pysnmp.hlapi.asyncio as hlapi

    if not cred.is_v3:
        # mpModel=1 → SNMPv2c (GetBulk, contadores de 64 bits).
        return hlapi.CommunityData(cred.community or "public", mpModel=1)

    auth_proto = getattr(hlapi, _AUTH_PROTO_NAMES.get(
        (cred.v3_auth_protocol or "").upper(), "usmNoAuthProtocol"))
    priv_proto = getattr(hlapi, _PRIV_PROTO_NAMES.get(
        (cred.v3_priv_protocol or "").upper(), "usmNoPrivProtocol"))

    # O nível efetivo depende de quais chaves foram fornecidas: sem authKey,
    # o pysnmp usa noAuth; sem privKey, noPriv. Passamos None quando ausente
    # para que a biblioteca aplique os protocolos "no*" corretos.
    auth_key = cred.v3_auth_key or None
    priv_key = cred.v3_priv_key or None
    if auth_key is None:
        auth_proto = hlapi.usmNoAuthProtocol
    if priv_key is None:
        priv_proto = hlapi.usmNoPrivProtocol

    return hlapi.UsmUserData(
        cred.v3_user or "",
        authKey=auth_key,
        privKey=priv_key,
        authProtocol=auth_proto,
        privProtocol=priv_proto,
    )


def _run_coro(coro, timeout: int):
    """Executa uma corrotina asyncio de forma síncrona, mesmo dentro de um
    loop em execução (delega a um thread próprio nesse caso)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result(timeout=timeout + 2)
    return asyncio.run(coro)


def snmp_get(
    ip: str,
    oid: str,
    community: str = "public",
    port: int = 161,
    timeout: int = 5,
    credential: "SnmpCredential | None" = None,
) -> str | None:
    """Faz um SNMP GET para um OID específico (wrapper síncrono).

    Aceita ``credential`` (v2c ou v3). Por retrocompatibilidade, se nenhuma
    credencial for passada usa ``community`` (v2c).

    Returns:
        Valor retornado como string, ou None se falhar.
    """
    cred = credential or SnmpCredential(version="2c", community=community)
    try:
        import pysnmp.hlapi.asyncio as hlapi
    except ImportError:
        logger.warning("pysnmp não instalado. Ignorando consulta SNMP.")
        return None

    async def _do_get():
        auth_data = _build_auth_data(cred)
        error_indication, error_status, error_index, var_binds = await hlapi.getCmd(
            hlapi.SnmpEngine(),
            auth_data,
            hlapi.UdpTransportTarget((ip, port), timeout=timeout, retries=1),
            hlapi.ContextData(),
            hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
        )

        if error_indication:
            logger.warning("SNMP error indication para %s: %s", ip, error_indication)
            return None
        if error_status:
            logger.warning(
                "SNMP error status para %s: %s at %s",
                ip, error_status.prettyPrint(),
                error_index and var_binds[int(error_index) - 1][0] or "?",
            )
            return None

        for name, val in var_binds:
            return str(val)
        return None

    try:
        return _run_coro(_do_get(), timeout)
    except Exception:
        logger.exception("Erro SNMP ao consultar %s (OID=%s)", ip, oid)
        return None


def snmp_walk(
    ip: str,
    base_oid: str,
    credential: "SnmpCredential | None" = None,
    community: str = "public",
    port: int = 161,
    timeout: int = 5,
    max_rows: int = 4096,
) -> list[tuple[str, str]]:
    """Percorre uma subárvore da MIB (SNMP WALK) e retorna [(oid, valor)].

    Usa GetBulk (v2c/v3). Para em ``max_rows`` linhas como guarda contra
    tabelas enormes. Lista vazia em falha ou pysnmp ausente.
    """
    cred = credential or SnmpCredential(version="2c", community=community)
    try:
        import pysnmp.hlapi.asyncio as hlapi
    except ImportError:
        logger.warning("pysnmp não instalado. Ignorando SNMP walk.")
        return []

    async def _do_walk():
        rows: list[tuple[str, str]] = []
        auth_data = _build_auth_data(cred)
        engine = hlapi.SnmpEngine()
        iterator = hlapi.bulkCmd(
            engine,
            auth_data,
            hlapi.UdpTransportTarget((ip, port), timeout=timeout, retries=1),
            hlapi.ContextData(),
            0, 25,  # nonRepeaters, maxRepetitions
            hlapi.ObjectType(hlapi.ObjectIdentity(base_oid)),
            lexicographicMode=False,  # para ao sair da subárvore base_oid
        )
        while True:
            error_indication, error_status, error_index, var_binds = await iterator
            if error_indication:
                logger.debug("SNMP walk error indication %s: %s", ip, error_indication)
                break
            if error_status:
                logger.debug("SNMP walk error status %s: %s", ip, error_status.prettyPrint())
                break
            if not var_binds:
                break
            for name, val in var_binds:
                rows.append((str(name), str(val)))
            if len(rows) >= max_rows:
                logger.warning("SNMP walk de %s (%s) truncado em %d linhas.", ip, base_oid, max_rows)
                break
        return rows

    try:
        return _run_coro(_do_walk(), timeout)
    except Exception:
        logger.exception("Erro SNMP walk em %s (base=%s)", ip, base_oid)
        return []


def get_system_info(
    ip: str,
    community: str = "public",
    credential: "SnmpCredential | None" = None,
) -> dict:
    """Coleta informações básicas do sistema via SNMP (v2c ou v3).

    Returns:
        Dicionário com chaves: sys_descr, sys_name, sys_uptime, sys_contact, sys_location.
        Se nenhum dado for retornado, inclui chave 'error'.
    """
    cred = credential or SnmpCredential(version="2c", community=community)
    info = {}
    oid_map = {
        "sys_descr": OID_SYS_DESCR,
        "sys_name": OID_SYS_NAME,
        "sys_uptime": OID_SYS_UPTIME,
        "sys_contact": OID_SYS_CONTACT,
        "sys_location": OID_SYS_LOCATION,
    }
    for key, oid in oid_map.items():
        value = snmp_get(ip, oid, credential=cred)
        if value is not None:
            info[key] = value

    if not info:
        info["error"] = f"Nenhuma resposta SNMP de {ip} (timeout ou agente SNMP desabilitado)."

    return info
