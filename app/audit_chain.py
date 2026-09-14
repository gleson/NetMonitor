"""Verificação da cadeia de integridade do AuditLog.

O audit log só tem valor se for confiável. Sem proteção, quem obtém acesso de
escrita ao banco pode editar ou apagar as linhas que registram a própria
invasão — e o registro passa a atestar exatamente o contrário do que aconteceu.

Cada entrada guarda o hash da anterior (``prev_hash``) e o hash do próprio
conteúdo encadeado a ele (``entry_hash``), atribuídos no listener
``models._chain_audit_logs``. Isso separa dois tipos de violação:

- **Conteúdo adulterado** — o hash recalculado da linha não bate com o gravado.
  É prova direta de edição: nenhuma condição de corrida produz esse resultado.
- **Encadeamento rompido** — o ``prev_hash`` de uma linha não corresponde ao
  ``entry_hash`` da anterior. Indica remoção ou reordenação, mas **também** pode
  vir de dois processos escrevendo ao mesmo tempo (ver o limite documentado no
  listener), por isso é reportado em categoria separada.

O que a cadeia **não** promete: ela prova que o registro não mudou *desde que
foi escrito*, não que ele é completo desde o início dos tempos. Duas
consequências honestas:

- Entradas anteriores à adoção da cadeia (ou criadas com ela desligada) ficam
  sem hash e são contadas como ``unchained`` — não verificáveis, não corrompidas.
- A retenção (``AUDIT_LOG_RETENTION_DAYS``) apaga entradas antigas por projeto.
  Por isso o ``prev_hash`` da **primeira** linha sobrevivente nunca é cobrado:
  só rupturas no meio da sequência são apontadas.

Quem consegue escrever no banco também consegue reescrever a cadeia inteira de
forma consistente. A proteção real é contra adulteração *pontual e silenciosa* —
o caso comum — e não substitui enviar o log para fora da máquina.
"""

import logging

logger = logging.getLogger(__name__)


def verify_audit_chain(limit: int | None = None, start_id: int | None = None) -> dict:
    """Recalcula a cadeia e devolve um laudo.

    Args:
        limit: verifica apenas as N entradas mais recentes (None = todas).
            A primeira entrada da janela tem o elo anterior dispensado, como no
            caso da retenção.
        start_id: ignora entradas com id menor que este.

    Returns:
        dict com ``ok`` (bool), ``checked``, ``unchained``, ``tampered``
        (ids com conteúdo alterado), ``broken_links`` (ids cujo elo não fecha),
        ``first_id``, ``last_id`` e ``summary`` (texto em pt-BR).
    """
    from app.extensions import db
    from app.models import AuditLog

    q = AuditLog.query
    if start_id is not None:
        q = q.filter(AuditLog.id >= start_id)

    if limit:
        # Pega as N mais recentes e reordena crescente para percorrer a cadeia.
        rows = list(reversed(q.order_by(AuditLog.id.desc()).limit(limit).all()))
    else:
        rows = q.order_by(AuditLog.id.asc()).all()

    result = {
        "ok": True, "checked": 0, "unchained": 0,
        "tampered": [], "broken_links": [],
        "first_id": rows[0].id if rows else None,
        "last_id": rows[-1].id if rows else None,
        "total": len(rows),
        "summary": "",
    }

    previous_hash = None  # entry_hash da última linha encadeada que vimos
    for entry in rows:
        if not entry.entry_hash:
            # Linha anterior à adoção da cadeia: não dá para verificar nem
            # acusar. Também zera o elo, senão a próxima linha encadeada seria
            # cobrada por um antecessor que nunca teve hash.
            result["unchained"] += 1
            previous_hash = None
            continue

        result["checked"] += 1

        if entry.compute_hash(entry.prev_hash or "") != entry.entry_hash:
            result["tampered"].append(entry.id)
            result["ok"] = False
            # Conteúdo alterado invalida tudo a jusante; seguimos a partir do
            # hash gravado para não transformar uma violação em cascata de ruído.
            previous_hash = entry.entry_hash
            continue

        # O elo só é cobrado quando existe um antecessor verificável nesta
        # janela — a primeira linha pode ter perdido o antecessor para a
        # retenção, ou ser o começo real da cadeia.
        if previous_hash is not None and entry.prev_hash != previous_hash:
            result["broken_links"].append(entry.id)
            result["ok"] = False

        previous_hash = entry.entry_hash

    result["summary"] = _summarize(result)
    if not result["ok"]:
        logger.warning("Cadeia do audit log inconsistente: %s", result["summary"])
    return result


def _summarize(r: dict) -> str:
    """Laudo em uma frase, em pt-BR, para UI e CLI."""
    if r["total"] == 0:
        return "Nenhuma entrada de audit log para verificar."

    partes = [f"{r['checked']} entrada(s) verificada(s)"]
    if r["unchained"]:
        partes.append(f"{r['unchained']} sem hash (anteriores à cadeia)")

    if r["ok"]:
        return "Íntegro — " + ", ".join(partes) + "."

    problemas = []
    if r["tampered"]:
        ids = ", ".join(str(i) for i in r["tampered"][:10])
        reticencias = "…" if len(r["tampered"]) > 10 else ""
        problemas.append(
            f"{len(r['tampered'])} entrada(s) com CONTEÚDO ALTERADO (id {ids}{reticencias})"
        )
    if r["broken_links"]:
        ids = ", ".join(str(i) for i in r["broken_links"][:10])
        reticencias = "…" if len(r["broken_links"]) > 10 else ""
        problemas.append(
            f"{len(r['broken_links'])} elo(s) rompido(s) — entrada removida ou "
            f"escrita concorrente (id {ids}{reticencias})"
        )
    return "VIOLAÇÃO — " + "; ".join(problemas) + f". {', '.join(partes)}."


def rebuild_audit_chain() -> int:
    """Reencadeia todas as entradas do zero, em ordem de id.

    Usado pela migration para dar hash ao histórico já existente. **Não** é uma
    correção de violação: rodar isto depois de uma adulteração faz a cadeia voltar
    a fechar sobre o conteúdo adulterado, apagando a evidência. Por isso não há
    caminho para cá pela interface web.

    Returns: quantidade de entradas encadeadas.
    """
    from app.extensions import db
    from app.models import AUDIT_CHAIN_GENESIS, AuditLog

    rows = AuditLog.query.order_by(AuditLog.id.asc()).all()
    prev = AUDIT_CHAIN_GENESIS
    for entry in rows:
        entry.prev_hash = prev
        entry.entry_hash = entry.compute_hash(prev)
        prev = entry.entry_hash
    db.session.commit()
    logger.info("Cadeia do audit log reconstruída: %d entrada(s).", len(rows))
    return len(rows)
