"""Testes da cadeia de integridade do audit log.

O que a cadeia promete: detectar edição de uma entrada (prova direta) e remoção
de uma entrada (elo rompido). O que ela não promete está testado também — o
corte da retenção pelo início não pode virar falso positivo, senão o alerta
perde credibilidade e passa a ser ignorado.
"""

import pytest
import sqlalchemy as sa

from app.audit_chain import rebuild_audit_chain, verify_audit_chain
from app.auth_utils import audit
from app.models import AUDIT_CHAIN_GENESIS, AuditLog


@pytest.fixture
def entradas(db):
    """Dez entradas encadeadas, em commits separados."""
    for i in range(10):
        audit(f"teste.acao{i}", "coisa", i, details=f"detalhe {i}")
        db.session.commit()
    return AuditLog.query.order_by(AuditLog.id).all()


# ---------------------------------------------------------------------------
# Encadeamento
# ---------------------------------------------------------------------------

def test_primeira_entrada_parte_do_genesis(db):
    audit("teste.primeira")
    db.session.commit()
    assert AuditLog.query.one().prev_hash == AUDIT_CHAIN_GENESIS


def test_cada_entrada_aponta_para_a_anterior(db, entradas):
    for anterior, atual in zip(entradas, entradas[1:]):
        assert atual.prev_hash == anterior.entry_hash


def test_hash_confere_com_o_conteudo(db, entradas):
    for e in entradas:
        assert e.compute_hash(e.prev_hash) == e.entry_hash


def test_varias_entradas_no_mesmo_flush(db):
    """session.new não tem ordem — a cadeia precisa de uma sequência estável."""
    audit("teste.a", details="a")
    audit("teste.b", details="b")
    audit("teste.c", details="c")
    db.session.commit()
    assert verify_audit_chain()["ok"] is True
    acoes = [e.action for e in AuditLog.query.order_by(AuditLog.id)]
    assert acoes == ["teste.a", "teste.b", "teste.c"]


def test_entrada_construida_direto_tambem_encadeia(db):
    """O listener cobre qualquer caminho, não só o helper audit()."""
    from app.extensions import db as _db
    _db.session.add(AuditLog(action="direto", username="x"))
    _db.session.commit()
    e = AuditLog.query.one()
    assert e.entry_hash and e.prev_hash == AUDIT_CHAIN_GENESIS


def test_created_at_e_fixado_antes_do_hash(db):
    """O default da coluna só valeria no INSERT — depois do hash."""
    audit("teste.data")
    db.session.commit()
    e = AuditLog.query.one()
    assert e.created_at is not None
    assert e.compute_hash(e.prev_hash) == e.entry_hash


# ---------------------------------------------------------------------------
# Detecção de violação
# ---------------------------------------------------------------------------

def test_cadeia_intacta_verifica_ok(db, entradas):
    r = verify_audit_chain()
    assert r["ok"] is True
    assert r["checked"] == 10
    assert r["tampered"] == [] and r["broken_links"] == []
    assert "Íntegro" in r["summary"]


def test_conteudo_editado_e_detectado(db, entradas):
    alvo = entradas[4]
    db.session.execute(sa.text(
        "UPDATE audit_logs SET action = 'login.success' WHERE id = :i"
    ), {"i": alvo.id})
    db.session.commit()
    db.session.expire_all()

    r = verify_audit_chain()
    assert r["ok"] is False
    assert r["tampered"] == [alvo.id]
    assert "CONTEÚDO ALTERADO" in r["summary"]


def test_detalhes_apagados_sao_detectados(db, entradas):
    """Esvaziar o campo details é a forma mais discreta de adulterar."""
    alvo = entradas[7]
    db.session.execute(sa.text(
        "UPDATE audit_logs SET details = '' WHERE id = :i"), {"i": alvo.id})
    db.session.commit()
    db.session.expire_all()
    assert verify_audit_chain()["tampered"] == [alvo.id]


def test_entrada_removida_rompe_o_elo(db, entradas):
    removida, seguinte = entradas[4], entradas[5]
    db.session.execute(sa.text("DELETE FROM audit_logs WHERE id = :i"),
                       {"i": removida.id})
    db.session.commit()
    db.session.expire_all()

    r = verify_audit_chain()
    assert r["ok"] is False
    assert r["broken_links"] == [seguinte.id]
    assert r["tampered"] == []
    assert "elo(s) rompido(s)" in r["summary"]


def test_retencao_no_inicio_nao_e_falso_positivo(db, entradas):
    """cleanup_old_data apaga as mais antigas por projeto — não é violação."""
    corte = entradas[3].id
    db.session.execute(sa.text("DELETE FROM audit_logs WHERE id < :i"), {"i": corte})
    db.session.commit()
    db.session.expire_all()

    r = verify_audit_chain()
    assert r["ok"] is True
    assert r["checked"] == 7


def test_janela_limitada_nao_e_falso_positivo(db, entradas):
    r = verify_audit_chain(limit=3)
    assert r["ok"] is True and r["checked"] == 3
    assert r["last_id"] == entradas[-1].id


def test_entradas_sem_hash_sao_contadas_sem_acusar(db, entradas):
    """Linhas anteriores à adoção da cadeia: não verificáveis, não corrompidas."""
    db.session.execute(sa.text(
        "UPDATE audit_logs SET entry_hash = '', prev_hash = '' WHERE id <= :i"
    ), {"i": entradas[2].id})
    db.session.commit()
    db.session.expire_all()

    r = verify_audit_chain()
    assert r["ok"] is True
    assert r["unchained"] == 3
    assert r["checked"] == 7
    assert "sem hash" in r["summary"]


def test_banco_vazio(db):
    r = verify_audit_chain()
    assert r["ok"] is True and r["total"] == 0
    assert "Nenhuma entrada" in r["summary"]


# ---------------------------------------------------------------------------
# Reconstrução
# ---------------------------------------------------------------------------

def test_rebuild_reencadeia_tudo(db, entradas):
    db.session.execute(sa.text("UPDATE audit_logs SET entry_hash = '', prev_hash = ''"))
    db.session.commit()
    db.session.expire_all()

    assert rebuild_audit_chain() == 10
    assert verify_audit_chain()["ok"] is True


def test_rebuild_nao_e_correcao_de_violacao(db, entradas):
    """Reconstruir sobre conteúdo adulterado faz a cadeia fechar de novo.

    É o motivo de rebuild_audit_chain não ter caminho pela interface web: ele
    apagaria justamente a evidência que a cadeia existe para preservar.
    """
    db.session.execute(sa.text(
        "UPDATE audit_logs SET action = 'mentira' WHERE id = :i"), {"i": entradas[4].id})
    db.session.commit()
    db.session.expire_all()
    assert verify_audit_chain()["ok"] is False

    rebuild_audit_chain()
    assert verify_audit_chain()["ok"] is True
    assert db.session.get(AuditLog, entradas[4].id).action == "mentira"
