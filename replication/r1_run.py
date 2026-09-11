"""R1：授权包含性质（spec §3.2 / §5 P1 / §7）。"""
from __future__ import annotations

import json

import mechanism as M
import patterns as P
from independent_check import allowed_entries_for, token_scope_of

UNIVERSE = {"order.read", "order.write", "db.export", "mail.send"}
R_A = {
    "order.read@orders/*",
    "order.write@orders/*",
    "db.export@reports/**",
    "mail.send@**",
}


def build():
    world = M.WorldModel()
    evidence = M.EvidencePlane()
    auth = M.Authority()
    grant = auth.issue_root_grant("A", R_A, now=0.0)
    peps = {
        s: M.PEP(s, world, evidence, auth) for s in ("A", "B", "C", "D", "E", "F")
    }
    for s, p in peps.items():
        p.peers = peps
    # §5：本级持有的根令牌由装入自己的授权建立
    peps["A"].install_grant(grant, 0.0)
    root_tok = peps["A"].root_token
    return world, evidence, auth, grant, peps, root_tok


NOW = 1000.0


def make_request(sender: M.PEP, to_id, token, cap, res, task_id, nonce, ts=None):
    req = M.ActionRequest(
        request_id=f"req-{nonce}",
        from_id=sender.subject_id,
        to_id=to_id,
        task_id=task_id,
        token_id=token.token_id,
        capability=cap,
        resource=res,
        nonce=nonce,
        ts=NOW if ts is None else ts,
    )
    req.sig_from_pep = M.sign(sender.sk, M._canon(req.body()))
    return req


def main():
    world, evidence, auth, grant, peps, root_tok = build()
    A, B, C, D, E, F = (peps[s] for s in "ABCDEF")

    # ------------------------------------------------ §3.1 四跳委托 A→B→C→D→E
    t1 = M.attenuate(
        root_tok, "B", {"order.read@orders/*", "db.export@reports/**"},
        "task-1", 500.0, A, NOW, grant,
    )
    assert B.receive_token(t1, NOW)[0]
    t2 = M.attenuate(t1, "C", {"order.read@orders/*"}, "task-1", 400.0, B, NOW, grant)
    assert C.receive_token(t2, NOW)[0]
    t3 = M.attenuate(t2, "D", {"order.read@orders/7"}, "task-1", 300.0, C, NOW, grant)
    assert D.receive_token(t3, NOW)[0]
    t4 = M.attenuate(t3, "E", {"order.read@orders/7"}, "task-1", 200.0, D, NOW, grant)
    assert E.receive_token(t4, NOW)[0]
    t5 = M.attenuate(t4, "F", {"order.read@orders/7"}, "task-1", 100.0, E, NOW, grant)
    assert F.receive_token(t5, NOW)[0]

    # ------------------------------------------------------------ 请求批次
    def send(sender, to, token, cap, res, nonce, task="task-1", ts=None):
        req = make_request(sender, to.subject_id, token, cap, res, task, nonce, ts)
        return to.handle(req, NOW)

    core = [
        ("A→B in-scope  order.read@orders/7", send(A, B, t1, "order.read", "orders/7", "n1")),
        ("A→B in-scope  db.export@reports/q3.csv", send(A, B, t1, "db.export", "reports/q3.csv", "n2")),
        ("A→B out-scope order.write@orders/7", send(A, B, t1, "order.write", "orders/7", "n3")),
        ("B→C in-scope  order.read@orders/7", send(B, C, t2, "order.read", "orders/7", "n4")),
        ("B→C out-scope db.export@reports/q3.csv", send(B, C, t2, "db.export", "reports/q3.csv", "n5")),
        ("C→D in-scope  order.read@orders/7", send(C, D, t3, "order.read", "orders/7", "n6")),
        ("C→D out-scope order.read@orders/9", send(C, D, t3, "order.read", "orders/9", "n7")),
        ("D→E in-scope  order.read@orders/7", send(D, E, t4, "order.read", "orders/7", "n8")),
        ("D→E out-scope mail.send@x@y", send(D, E, t4, "mail.send", "a@b", "n9")),
    ]
    effects_after_core = len(world.effects)

    attacks = [
        ("replay same nonce", send(A, B, t1, "order.read", "orders/7", "n1")),
        ("E 用 t1 请求 B（签发者非 E）", send(E, B, t1, "order.read", "orders/7", "n10")),
        ("A 用不在 B 库中的 t4", send(A, B, t4, "order.read", "orders/7", "n11")),
        ("task 绑定不符", send(A, B, t1, "order.read", "orders/7", "n12", task="task-2")),
        ("请求时窗外", send(A, B, t1, "order.read", "orders/7", "n13", ts=NOW - 10_000)),
    ]

    # -------------------------------------------------------- 派生尝试
    derivations = []

    def try_derive(label, parent, holder, scope, actor, kind, task="task-1", ttl=50.0):
        try:
            t = M.attenuate(parent, holder, scope, task, ttl, actor, NOW, grant)
            derivations.append((label, kind, "SUCCESS", sorted(t.scope)))
        except M.DerivationRejected as e:
            derivations.append((label, kind, e.code, sorted(scope)))

    # 合法派生（非平凡性：必须存在成功路径）
    try_derive("B 从 t1 授出 t2（合法）", t1, "C", {"order.read@orders/*"}, B, "legit")
    try_derive("E 从 t4 授出 t5（合法）", t4, "F", {"order.read@orders/7"}, E, "legit")
    # 越权派生尝试（必须全部被拒）
    try_derive("B 授出 order.write（t1 中无）", t1, "C", {"order.write@orders/*"}, B, "over")
    try_derive("C 授出 db.export（t2 中无）", t2, "F", {"db.export@reports/**"}, C, "over")
    try_derive("D 把 orders/7 放宽成 orders/*", t3, "F", {"order.read@orders/*"}, D, "over")
    try_derive("非持有者 A 拿 t2 派生", t2, "F", {"order.read@orders/7"}, A, "over")

    # 非转委托封条
    sealed = M.attenuate(root_tok, "B", {"order.read@orders/*"}, "task-1", 400.0, A, NOW, grant)
    sealed.redelegatable = False
    sealed.token_id = sealed.recompute_id()
    B.receive_token(sealed, NOW)
    try_derive("对 redelegatable=False 的令牌派生", sealed, "F", {"order.read@orders/7"}, B, "over")


    # ------------------------------------------------------- §7 不变式（独立重算）
    i2_violations = []
    for rec in evidence.receipts:
        if rec.decision != "ALLOW":
            continue
        tok = B.store.get(rec.token_id) or C.store.get(rec.token_id) or \
              D.store.get(rec.token_id) or E.store.get(rec.token_id) or \
              F.store.get(rec.token_id)
        entries = allowed_entries_for(tok, rec.capability, rec.resource)
        if not entries:
            i2_violations.append(rec.receipt_id)

    out = {
        "scope_entries": {
            "R_A": sorted(R_A),
            "t1 A→B": sorted(t1.scope), "t2 B→C": sorted(t2.scope),
            "t3 C→D": sorted(t3.scope), "t4 D→E": sorted(t4.scope),
        },
        "core": [(l, r.decision, r.reason_code) for l, r in core],
        "attacks": [(l, r.decision, r.reason_code) for l, r in attacks],
        "derivations": derivations,
        "n_allow": sum(1 for _, r in core + attacks if r.decision == "ALLOW"),
        "n_deny": sum(1 for _, r in core + attacks if r.decision == "DENY"),
        "core_deny_by_code": {},
        "side_effects_total": len(world.effects),
        "side_effects_after_core": effects_after_core,
        "out_of_scope_side_effects": 0,
        "over_derivation_success": sum(1 for _, k, st, _ in derivations if k == "over" and st == "SUCCESS"),
        "legit_derivation_success": sum(1 for _, k, st, _ in derivations if k == "legit" and st == "SUCCESS"),
        "over_derivation_attempts": sum(1 for _, k, _, _ in derivations if k == "over"),
        "i2_violations": i2_violations,
        "n_receipts": len(evidence.receipts),
        "n_checks_passed": sum(1 for _, r in core + attacks if r.decision == "OK") + sum(
            1 for _, k, st, _ in derivations if st != "SUCCESS"
        ),
    }
    for l, r in core:
        if r.decision == "DENY":
            out["core_deny_by_code"][r.reason_code] = (
                out["core_deny_by_code"].get(r.reason_code, 0) + 1
            )

    # 越界请求的副作用判定：任何副作用的能力必须不在其令牌范围内才算越界
    allowed_scope_mismatch = 0
    for eff in world.effects:
        tok = next(
            (p.store.get(rec.token_id) for rec in evidence.receipts
             if rec.request_id == eff["request_id"]
             for p in peps.values() if rec.token_id in p.store),
            None,
        )
        if tok is None or not P.scope_allows(set(tok.scope), eff["capability"], eff["resource"]):
            allowed_scope_mismatch += 1
    out["allowed_actions_outside_token_scope"] = allowed_scope_mismatch
    out["out_of_scope_side_effects"] = allowed_scope_mismatch

    print(json.dumps(out, ensure_ascii=False, indent=2))
    return out


if __name__ == "__main__":
    main()
