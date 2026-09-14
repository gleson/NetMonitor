"""Configurações da aplicação."""

import os

basedir = os.path.abspath(os.path.dirname(__file__))

_DEV_SECRET_KEY = "dev-secret-key-troque-em-prod"


class Config:
    """Configurações base compartilhadas por todos os ambientes."""

    SECRET_KEY = os.environ.get("SECRET_KEY", _DEV_SECRET_KEY)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(basedir, '..', 'instance', 'netmonitor.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- SQLite: espera por lock de escrita ---
    # Os jobs do scheduler rodam em threads paralelas e escrevem no mesmo arquivo.
    # O default do pysqlite (5s) é curto demais: um job que escreve enquanto outro
    # segura o lock estoura "database is locked" e aborta a rodada. Ignorado em
    # backends não-SQLite. Ver _configure_sqlite_pragmas em app/__init__.py.
    SQLITE_BUSY_TIMEOUT_SECONDS = int(os.environ.get("SQLITE_BUSY_TIMEOUT_SECONDS", 30))

    # --- Cookies de sessão ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    # Duração do cookie "remember me"
    REMEMBER_COOKIE_DURATION = 60 * 60 * 24 * 14  # 14 dias

    # --- Rate limit ---
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # --- Bloqueio de conta por tentativas de login falhas ---
    # Após LOGIN_MAX_FAILED_ATTEMPTS falhas (por usuário + IP de origem) dentro
    # da janela LOGIN_LOCKOUT_MINUTES, novas tentativas daquele IP são bloqueadas
    # até a janela expirar ou um login bem-sucedido. 0 desativa o bloqueio
    # (mantém só o rate-limit/IP).
    LOGIN_MAX_FAILED_ATTEMPTS = int(os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS", 5))
    LOGIN_LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", 15))
    # Backstop global (soma de falhas de QUALQUER IP): protege contra brute-force
    # distribuído sem permitir que um único IP hostil bloqueie o usuário legítimo.
    # 0 desativa o limite global (fica só o por-IP).
    LOGIN_MAX_FAILED_ATTEMPTS_GLOBAL = int(
        os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS_GLOBAL", 30)
    )

    # --- Reconfirmação de identidade ("sudo mode") ---
    # Ações sensíveis (gestão de usuários, ajustes de scan, token de métricas)
    # exigem reconfirmar a identidade — código TOTP se o 2FA estiver ativo, ou
    # a senha da conta. A confirmação vale por esta janela (minutos) para não
    # pedir o código a cada clique dentro de um fluxo administrativo.
    SUDO_GRACE_MINUTES = int(os.environ.get("SUDO_GRACE_MINUTES", 10))

    # --- Intervalos padrão de scan (em minutos) ---
    DEFAULT_HOST_DISCOVERY_INTERVAL = 45
    DEFAULT_PORT_SCAN_INTERVAL = 4

    # --- Portas padrão para scan ---
    DEFAULT_SCAN_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5432,5900,8080,8443"

    # --- Limites de concorrência ---
    DEFAULT_MAX_CONCURRENT_SCANS = 3

    # --- Delay entre scans de hosts individuais (segundos) ---
    SCAN_INTER_HOST_DELAY = 0.3

    # --- Threshold para considerar host "online" (minutos) ---
    # Deve ser >= 2× o host_discovery_interval_minutes do perfil (padrão 45 min)
    # para tolerar reinicios do app e falhas pontuais de discovery sem falso-offline.
    HOST_ONLINE_THRESHOLD_MINUTES = 70

    # --- Paginação ---
    ITEMS_PER_PAGE = 25

    # --- Fuso horário local (offset em horas relativo a UTC) ---
    # BRT (Brasília) = -3
    LOCAL_TIMEZONE_OFFSET = -3

    # --- APScheduler ---
    SCHEDULER_API_ENABLED = False

    # --- Alertas HOST_DOWN ---
    # Quick check: ping leve (ICMP/ARP/TCP) em hosts com alert_on_down=True.
    # Default 5 min. Editável em /admin/scan-settings (chave 'host_down_quick_check_interval').
    # Após 2 falhas consecutivas, gera alerta CRITICAL is_priority=True.
    HOST_DOWN_QUICK_CHECK_INTERVAL_MINUTES = 5

    # --- Retenção de dados ---
    # 0 = sem limpeza automática. Job roda diariamente.
    SCAN_RETENTION_DAYS = int(os.environ.get("SCAN_RETENTION_DAYS", 30))
    ALERT_RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", 90))
    SNAPSHOT_RETENTION_DAYS = int(os.environ.get("SNAPSHOT_RETENTION_DAYS", 180))
    AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", 365))
    # Quantas entradas recentes a tela /admin/audit confere a cada carregamento.
    # Verificar o histórico inteiro não escala; o valor prático está no fim da
    # cadeia, que é onde um invasor apagaria o próprio rastro. Auditoria
    # completa fica no CLI: `flask verify-audit-chain`.
    AUDIT_CHAIN_UI_LIMIT = int(os.environ.get("AUDIT_CHAIN_UI_LIMIT", 500))

    # --- Notificações (webhook / SMTP) ---
    NOTIFICATIONS_ENABLED = os.environ.get("NOTIFICATIONS_ENABLED", "1") == "1"
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "netmonitor@localhost")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1") == "1"

    # --- Backup ---
    # Diretório onde `flask backup-db` grava os arquivos. Padrão: ./backups
    BACKUP_DIR = os.environ.get("BACKUP_DIR", os.path.join(basedir, "..", "backups"))
    # Backup automático agendado. 0 = desativado (use cron/`flask backup-db`).
    BACKUP_INTERVAL_HOURS = int(os.environ.get("BACKUP_INTERVAL_HOURS", 24))
    # Remove backups .db.gz mais antigos que N dias. 0 = mantém todos.
    BACKUP_RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", 30))

    # --- Criptografia de credenciais SNMP (Fernet) ---
    # Gere com: flask generate-fernet-key
    # Sem esta variável, a community é armazenada em texto puro.
    FERNET_KEY = os.environ.get("FERNET_KEY", "")

    # --- Correlação CVE (NVD) ---
    # Job diário que correlaciona service_name/service_version das portas
    # abertas com CVEs conhecidos via API do NVD. Não gera tráfego na rede
    # local (só consultas HTTPS externas, com cache em cve_cache).
    CVE_LOOKUP_ENABLED = os.environ.get("CVE_LOOKUP_ENABLED", "1") == "1"
    CVE_LOOKUP_INTERVAL_HOURS = int(os.environ.get("CVE_LOOKUP_INTERVAL_HOURS", 24))
    CVE_CACHE_TTL_DAYS = int(os.environ.get("CVE_CACHE_TTL_DAYS", 7))
    # CVSS mínimo para registrar Vulnerability + alerta (>=9.0 vira CRITICAL).
    CVE_MIN_CVSS_ALERT = float(os.environ.get("CVE_MIN_CVSS_ALERT", 7.0))
    # Máximo de consultas não-cacheadas à API por execução (rate-limit NVD).
    CVE_MAX_LOOKUPS_PER_RUN = int(os.environ.get("CVE_MAX_LOOKUPS_PER_RUN", 30))
    # API key do NVD (opcional). Com chave o limite sobe de ~5 para ~50 req/30s
    # e a pausa entre consultas cai de 6.5s para 0.7s. Solicite em
    # https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    # Catálogo CISA KEV (vulnerabilidades sob exploração ativa) — feed público,
    # sem LLM nem API key. CVEs em KEV viram alerta CRITICAL is_priority=True.
    CVE_KEV_ENABLED = os.environ.get("CVE_KEV_ENABLED", "1") == "1"
    CVE_KEV_REFRESH_HOURS = int(os.environ.get("CVE_KEV_REFRESH_HOURS", 24))

    # --- Check rápido de portas críticas ---
    # Escaneia apenas CRITICAL_PORTS (~11 portas) nos devices online a cada
    # N minutos — detecta exposição grave em horas em vez de 24h, com tráfego
    # mínimo. 0 desativa.
    CRITICAL_PORTS_CHECK_INTERVAL_MINUTES = int(
        os.environ.get("CRITICAL_PORTS_CHECK_INTERVAL_MINUTES", 120)
    )

    # --- Scan UDP ---
    # Scan semanal de um conjunto pequeno de portas UDP (DNS, SNMP, NTP,
    # NetBIOS, SSDP...). Requer root (-sU usa raw sockets). 0 desativa.
    UDP_SCAN_INTERVAL_HOURS = int(os.environ.get("UDP_SCAN_INTERVAL_HOURS", 168))

    # --- Verificação de certificados TLS ---
    # Checa expiração de certificados em portas HTTPS abertas. 0 desativa.
    TLS_CHECK_INTERVAL_HOURS = int(os.environ.get("TLS_CHECK_INTERVAL_HOURS", 24))
    TLS_CERT_WARN_DAYS = int(os.environ.get("TLS_CERT_WARN_DAYS", 15))

    # --- Qualidade da configuração TLS ---
    # Além da expiração, avalia o que o servidor negocia: versão do protocolo,
    # algoritmo de assinatura do certificado e tamanho da chave. Roda dentro do
    # job TLS (mesma conexão, custo zero adicional). Re-alerta só depois de
    # TLS_QUALITY_RECHECK_DAYS — achado de configuração não muda sozinho.
    TLS_QUALITY_ENABLED = os.environ.get("TLS_QUALITY_ENABLED", "1") == "1"
    TLS_QUALITY_RECHECK_DAYS = int(os.environ.get("TLS_QUALITY_RECHECK_DAYS", 30))

    # --- Mudança de serviço/versão em portas conhecidas ---
    # Alerta quando o banner (-sV) de uma porta já mapeada muda. Pega tanto
    # atualização legítima quanto troca de equipamento no mesmo IP.
    SERVICE_CHANGE_ALERTS_ENABLED = os.environ.get("SERVICE_CHANGE_ALERTS_ENABLED", "1") == "1"
    SERVICE_CHANGE_DEDUP_HOURS = int(os.environ.get("SERVICE_CHANGE_DEDUP_HOURS", 24))

    # --- Configurações inseguras conhecidas (SMB / SNMP) ---
    # Procura o que dispensa CVE nenhum: SMBv1 ligado, assinatura SMB não
    # exigida e comunidade SNMP de fábrica ainda aceita. Não requer root.
    # 0 no intervalo desativa.
    HARDENING_CHECKS_ENABLED = os.environ.get("HARDENING_CHECKS_ENABLED", "1") == "1"
    HARDENING_CHECK_INTERVAL_HOURS = int(os.environ.get("HARDENING_CHECK_INTERVAL_HOURS", 24))
    # SNMP é UDP/161 e só apareceria no scan UDP semanal (que exige root) —
    # justamente os equipamentos que mais têm comunidade padrão (impressora,
    # câmera, ponto de acesso) ficariam de fora. Por isso, por padrão, a
    # comunidade é testada em todo ativo online: um pacote UDP por comunidade.
    HARDENING_SNMP_PROBE_ALL = os.environ.get("HARDENING_SNMP_PROBE_ALL", "1") == "1"
    # A sondagem é paralela: serialmente, os timeouts de SNMP e os scans NSE se
    # somam host a host e o job levaria minutos numa rede grande.
    HARDENING_MAX_WORKERS = int(os.environ.get("HARDENING_MAX_WORKERS", 10))

    # --- Integridade do DNS ---
    # Resolve domínios âncora (IPs públicos e estáveis) pelos servidores DNS da
    # rede e compara com o esperado; também vigia a própria lista de
    # resolvedores. 0 desativa. Requer saída UDP/53 para os servidores da rede.
    DNS_CHECK_ENABLED = os.environ.get("DNS_CHECK_ENABLED", "1") == "1"
    DNS_CHECK_INTERVAL_HOURS = int(os.environ.get("DNS_CHECK_INTERVAL_HOURS", 6))
    DNS_QUERY_TIMEOUT = float(os.environ.get("DNS_QUERY_TIMEOUT", 3))

    # --- Métricas Prometheus ---
    # Endpoint /api/metrics/prometheus (texto Prometheus, sem login). Desligado
    # por padrão para não expor contagens da rede sem intenção explícita. Quando
    # METRICS_TOKEN está definido, o scrape precisa enviá-lo em
    # `Authorization: Bearer <token>` ou `?token=`; vazio deixa o endpoint aberto
    # (cenário de scrape em localhost/rede confiável).
    METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "0") == "1"
    METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")

    # --- Descoberta passiva por sniffing de ARP ---
    # Escuta o tráfego ARP da sub-rede em background para detectar dispositivos
    # novos em segundos (complementa o discovery ativo). Requer root. Desligada
    # por padrão; pode ser ligada em runtime via /admin/scan-settings
    # (AppSetting 'passive_arp_enabled').
    PASSIVE_ARP_DISCOVERY_ENABLED = os.environ.get("PASSIVE_ARP_DISCOVERY_ENABLED", "0") == "1"

    # --- Topologia física de camada 2 (LLDP + FDB via SNMP) ---
    # Job opcional que mapeia em qual porta de switch cada ativo está conectado,
    # correlacionando LLDP-MIB e BRIDGE-MIB (FDB) dos devices do tipo SWITCH.
    # Requer switches gerenciáveis com SNMP. Desligado por padrão; ligável em
    # runtime via /admin/scan-settings (AppSetting 'topology_lldp_enabled').
    TOPOLOGY_LLDP_ENABLED = os.environ.get("TOPOLOGY_LLDP_ENABLED", "0") == "1"
    TOPOLOGY_LLDP_INTERVAL_HOURS = int(os.environ.get("TOPOLOGY_LLDP_INTERVAL_HOURS", 6))
    # Alerta MAC_PORT_CONFLICT: mesmo MAC aprendido em portas de acesso
    # distintas. Sai de graça da coleta acima — não faz consulta nova.
    TOPOLOGY_MAC_PORT_ALERTS = os.environ.get("TOPOLOGY_MAC_PORT_ALERTS", "1") == "1"
    # Acima de quantos MACs distintos uma porta é tratada como uplink (e não
    # como tomada de endpoint). Uplink carrega a rede inteira; porta de acesso
    # carrega um ou dois endereços. Complementa o LLDP, cujo rótulo de porta
    # local nem sempre coincide com o ifName usado pela FDB.
    TOPOLOGY_UPLINK_MAC_THRESHOLD = int(os.environ.get("TOPOLOGY_UPLINK_MAC_THRESHOLD", 4))
    MAC_PORT_ALERT_DEDUP_HOURS = int(os.environ.get("MAC_PORT_ALERT_DEDUP_HOURS", 12))

    # --- Vigilância do ambiente Wi-Fi (ponto de acesso não autorizado) ---
    # Lê as redes ao alcance via NetworkManager (nmcli). Não exige root nem modo
    # monitor. Só alerta para os SSIDs marcados como vigiados no perfil.
    WIFI_WATCH_ENABLED = os.environ.get("WIFI_WATCH_ENABLED", "1") == "1"
    WIFI_SCAN_INTERVAL_HOURS = int(os.environ.get("WIFI_SCAN_INTERVAL_HOURS", 1))

    # --- Descoberta e monitoramento IPv6 ---
    # Complementa a descoberta ARP/IPv4 lendo a tabela de vizinhança IPv6 (NDP)
    # do kernel. Os endereços encontrados são agrupados no ativo já existente
    # pelo MAC — IPv4 e IPv6 coexistem no mesmo device, não competem.
    # Não requer root: usa ICMPv6 multicast (ff02::1) + 'ip -6 neigh'.
    IPV6_DISCOVERY_ENABLED = os.environ.get("IPV6_DISCOVERY_ENABLED", "1") == "1"
    # Cataloga também os link-local (fe80::), que todo host IPv6 possui. São
    # ruidosos (um por interface), mas provam que a pilha IPv6 está ativa mesmo
    # em redes sem endereçamento global.
    IPV6_INCLUDE_LINK_LOCAL = os.environ.get("IPV6_INCLUDE_LINK_LOCAL", "1") == "1"
    # Endereços IPv6 não vistos há mais de N dias deixam de ser "atuais".
    # Necessário por causa das privacy extensions (RFC 4941): Windows, Android e
    # iOS trocam de endereço temporário a cada ~24h e, sem expiração, o ativo
    # acumularia dezenas de IPv6 mortos na tela.
    IPV6_ADDRESS_RETENTION_DAYS = int(os.environ.get("IPV6_ADDRESS_RETENTION_DAYS", 30))
    # Port scan sobre o IPv6 global/ULA dos ativos (nmap -6), em job separado.
    # Existe porque regras de firewall costumam divergir entre as duas famílias:
    # uma porta bloqueada no IPv4 pode estar exposta no IPv6. 0 desabilita.
    IPV6_PORT_SCAN_INTERVAL_HOURS = int(os.environ.get("IPV6_PORT_SCAN_INTERVAL_HOURS", 12))

    # --- Detecção de man-in-the-middle ---
    # Agrupa as checagens anti-MITM: integridade do MAC do gateway padrão,
    # ARP/NDP spoofing detectado pelo sniffer passivo, servidor DHCP e Router
    # Advertisement IPv6 não autorizados, e troca de certificado TLS.
    # Todas são passivas ou de custo desprezível — nenhuma gera varredura.
    MITM_DETECTION_ENABLED = os.environ.get("MITM_DETECTION_ENABLED", "1") == "1"

    # --- Dedupe de alertas de porta ---
    # Não re-emite o mesmo alerta (device+porta) dentro desta janela, evitando
    # spam quando o estado oscila (flapping filtered<->open).
    PORT_ALERT_DEDUP_HOURS = int(os.environ.get("PORT_ALERT_DEDUP_HOURS", 6))

    @classmethod
    def validate(cls):
        """Hook para validação específica por ambiente. Override em subclasses."""
        return


class DevelopmentConfig(Config):
    DEBUG = True
    # Em dev, HTTP é ok — não forçar HTTPS nem cookies secure.
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    # Cookies só trafegam sobre HTTPS em produção.
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True

    @classmethod
    def validate(cls):
        if not os.environ.get("SECRET_KEY") or os.environ.get("SECRET_KEY") == _DEV_SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY deve ser definida via variável de ambiente em produção. "
                "Gere uma chave forte com `python -c 'import secrets; print(secrets.token_hex(32))'`."
            )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    # Desativa rate-limit e HTTPS forçado nos testes.
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    # Sem chamadas de rede externas em testes.
    CVE_LOOKUP_ENABLED = False
    CVE_KEV_ENABLED = False


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
