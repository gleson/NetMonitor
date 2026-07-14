#!/usr/bin/env bash
# Inicia o NetMonitor como root de forma restrita.
#
# Por quê root: várias partes do scanner checam os.geteuid() == 0 direto
# (app/scanner/hosts.py, ports.py, scheduling.py, passive.py, mobile.py) para
# decidir entre ARP scan/-sS/-sU/sniffing passivo (root) e os fallbacks sem
# privilégio (-sT, nmap host discovery). Rodar `setcap` no python ou no nmap
# NÃO ativa esses recursos, porque o código olha o uid do processo, não as
# capabilities do binário — por isso o processo Flask inteiro precisa ter
# euid 0 durante toda a execução (o sniffing passivo e os jobs agendados
# rodam em background pelo tempo de vida do processo, não é só um subprocesso
# nmap pontual).
#
# "De forma segura" aqui significa: euid 0 (exigido pelo código acima), mas
# com o *bounding set* de capabilities do processo restrito a só o que o
# scanner usa (rede) + o mínimo de acesso a arquivo para não quebrar leitura/
# escrita do banco e dos backups (que pertencem ao usuário normal, não a
# root). Capabilities perigosas e desnecessárias para este app (CAP_SYS_ADMIN,
# CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SETUID/SETGID etc.) ficam de fora do
# bounding set — mesmo como root, o processo (e tudo que ele executar, como o
# nmap) nunca consegue adquiri-las. Além disso: ambiente do processo é
# reconstruído do zero (não herda variáveis arbitrárias de quem chamou sudo),
# os caminhos de python/gunicorn são absolutos (sem depender do PATH) e os
# arquivos criados como root em instance/ e backups/ voltam a pertencer ao
# usuário normal ao final, para não travar a próxima execução sem root.
#
# Uso:
#   sudo scripts/start_root.sh dev             # flask run (debug, recarregador)
#   sudo scripts/start_root.sh prod            # gunicorn
#   sudo HOST=0.0.0.0 PORT=8443 scripts/start_root.sh prod
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python3"
VENV_GUNICORN="$PROJECT_DIR/venv/bin/gunicorn"
ENV_FILE="$PROJECT_DIR/.env"
MODE="${1:-dev}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-${MODE_PORT:-}}"

if [[ "$MODE" != "dev" && "$MODE" != "prod" ]]; then
    echo "uso: $0 [dev|prod]" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Precisa rodar como root (ARP scan, -sS, -sU e descoberta passiva exigem euid 0)." >&2
    echo "Reexecute com: sudo $0 $MODE" >&2
    exit 1
fi

if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "venv não encontrado em $VENV_PYTHON — crie com:" >&2
    echo "  python -m venv venv && source venv/bin/activate && pip install -r requirements.txt" >&2
    exit 1
fi

NMAP_BIN="$(command -v nmap || true)"
if [[ -z "$NMAP_BIN" ]]; then
    echo "nmap não encontrado no PATH." >&2
    exit 1
fi

# Dono original (quem chamou sudo) — usado só para devolver a posse dos
# arquivos criados/tocados como root em instance/ e backups/ ao final.
ORIGINAL_USER="${SUDO_USER:-}"
if [[ -z "$ORIGINAL_USER" ]]; then
    ORIGINAL_USER="$(stat -c '%U' "$PROJECT_DIR")"
fi
ORIGINAL_GROUP="$(id -gn "$ORIGINAL_USER" 2>/dev/null || echo "$ORIGINAL_USER")"

restore_ownership() {
    for dir in instance backups; do
        if [[ -d "$PROJECT_DIR/$dir" ]]; then
            chown -R "$ORIGINAL_USER:$ORIGINAL_GROUP" "$PROJECT_DIR/$dir" 2>/dev/null || true
        fi
    done
    # Devolve também o lockfile do scheduler em /tmp: se ficar pertencendo a
    # root, uma execução posterior sem root não consegue reabri-lo para
    # escrita e rodaria sem scheduler.
    chown "$ORIGINAL_USER:$ORIGINAL_GROUP" /tmp/netmonitor-scheduler-*.lock 2>/dev/null || true
}
trap restore_ownership EXIT

# Ambiente limpo: não herdamos variáveis arbitrárias de quem chamou sudo
# (sudo -E passaria LD_PRELOAD, PYTHONPATH etc. de um shell não confiável
# para um processo root). Só entram PATH fixo (sem procurar em diretórios
# do usuário) e as chaves KEY=VALUE do .env do projeto.
CLEAN_ENV=(
    "PATH=$PROJECT_DIR/venv/bin:/usr/bin:/bin"
    "FLASK_APP=manage.py"
    "HOME=$PROJECT_DIR"
)
if [[ -f "$ENV_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line//[[:space:]]/}" ]] && continue
        if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
            CLEAN_ENV+=("$line")
        fi
    done < "$ENV_FILE"
fi

# Arquivos novos criados como root (log, journal do sqlite, backups) saem
# com permissão de leitura para o dono normal — writable só pelo dono root
# do processo, mas restore_ownership() acima já devolve a posse ao sair.
umask 022

# Capabilities: mantém root (euid 0, exigido pelo código do scanner) mas
# restringe o bounding set ao necessário — rede crua (ARP/-sS/-sU/sniffing)
# e acesso a arquivo (dac_override/dac_read_search: instance/ e backups/
# pertencem ao usuário normal, não a root; chown/fowner/fsetid: para o
# restore_ownership() acima e para o SQLite trocar dono/permissão de
# arquivos de journal). Tudo mais que um root "de verdade" teria
# (CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SETUID/SETGID,
# CAP_SYS_BOOT...) fica fora do bounding set — nem o processo Flask nem
# nenhum subprocesso que ele lançar (nmap incluso) conseguem adquirir essas
# capabilities, mesmo sendo root.
KEEP_CAPS="net_raw,net_admin,net_bind_service,dac_override,dac_read_search,chown,fowner,fsetid"

run_privileged() {
    if command -v setpriv >/dev/null 2>&1; then
        env -i "${CLEAN_ENV[@]}" setpriv \
            --bounding-set="-all,+${KEEP_CAPS//,/,+}" \
            --inh-caps="-all,+net_raw,+net_admin,+net_bind_service" \
            --ambient-caps="+net_raw,+net_admin,+net_bind_service" \
            --no-new-privs \
            "$@"
    else
        echo "aviso: 'setpriv' (pacote util-linux) não encontrado — rodando como root SEM restringir capabilities." >&2
        env -i "${CLEAN_ENV[@]}" "$@"
    fi
}

cd "$PROJECT_DIR"

case "$MODE" in
    dev)
        PORT="${PORT:-5000}"
        echo "Iniciando NetMonitor (dev, root com capabilities restritas) em http://$HOST:$PORT"
        run_privileged "$VENV_PYTHON" -m flask run --host="$HOST" --port="$PORT"
        ;;
    prod)
        if [[ ! -x "$VENV_GUNICORN" ]]; then
            echo "gunicorn não encontrado em $VENV_GUNICORN — instale com 'pip install -r requirements.txt'." >&2
            exit 1
        fi
        PORT="${PORT:-8000}"
        echo "Iniciando NetMonitor (prod, root com capabilities restritas) em http://$HOST:$PORT"
        # --workers 1: o scheduler dos scans roda dentro do processo; mais
        # workers exigiria o lock de flock descrito no CLAUDE.md e só o
        # primeiro worker teria os scans privilegiados mesmo assim.
        run_privileged "$VENV_GUNICORN" --workers 1 --bind "$HOST:$PORT" 'manage:app'
        ;;
esac
