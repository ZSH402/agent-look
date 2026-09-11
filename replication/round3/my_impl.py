"""Independent implementation of the pinned spec clauses, written from spec/spec.md ONLY.

No reference-implementation code was read. Where the spec leaves a choice open the
chosen reading is marked `CHOICE-n` and listed in REPORT.md.
"""

# ---------------------------------------------------------------- reason codes
OK = "OK"
SCOPE_VIOLATION = "SCOPE_VIOLATION"
TOKEN_EXPIRED = "TOKEN_EXPIRED"
TOKEN_REVOKED = "TOKEN_REVOKED"
TOKEN_INVALID = "TOKEN_INVALID"
NOT_REDELEGATABLE = "NOT_REDELEGATABLE"


# ------------------------------------------------- §2.3 verify (offline part)
def involved_key_epochs(token, grant):
    """CHOICE-1: 'all involved key_epoch' (rule 6) = root grant's epoch plus every
    link's attenuator_key_epoch. Holder/issuer epochs are NOT involved."""
    eps = []
    if grant is not None:
        eps.append((grant["subject_id"], grant["key_epoch"]))
    for lk in token["chain"]:
        eps.append((lk["attenuator_id"], lk["attenuator_key_epoch"]))
    return eps


def verify_reason(token, grant, now, revoked_token_ids, revoked_subject_ids,
                  revoked_key_upper, chain_broken=False, subject_scope="holder"):
    """Pinned priority (line 70): revoke -> expire -> key epoch; rules 1-3,7 after.

    Argument `token` is a dict with the §2.3 fields; `revoked_key_upper` maps
    subject_id -> highest revoked epoch (inclusive).
    """
    # rule 5 (revocation) has priority over everything in 4-6
    if token["token_id"] in revoked_token_ids:
        return TOKEN_REVOKED
    # CHOICE-6: the spec names neither the holder nor the root as the subject
    # checked by revoke_subject; "holder" is the reading the reference uses.
    subj = token["holder_id"] if subject_scope == "holder" else token["root_subject_id"]
    if subj in revoked_subject_ids:
        return TOKEN_REVOKED
    # rule 4 (expiry) is the second level
    if now > token["not_after"]:
        return TOKEN_EXPIRED
    # rule 6 (key epoch) is the third level; failure reports TOKEN_REVOKED (line 62)
    for sid, ep in involved_key_epochs(token, grant):
        if ep <= revoked_key_upper.get(sid, 0):
            return TOKEN_REVOKED
    # rules 1,2,3,7 -> not pinned against each other; any failure is TOKEN_INVALID
    if chain_broken:
        return TOKEN_INVALID
    return OK


# ------------------------------------------------- §2.3 attenuate (derivation)
def attenuate_reason(parent_held_by_delegator, parent_holder_id, delegator,
                     child_scope, parent_scope, parent_redelegatable,
                     child_scope_in_parent=True):
    """Rules 1-5 in the order the spec lists them (line 46: listing order == check order).

    CHOICE-2: 'holds' means 'is in the delegator's local token store' (§3.1: the
    delegator keeps no usable copy), not 'holds a Python reference'.
    CHOICE-3: rule 2's rejection code is not named in the spec; chosen SCOPE_VIOLATION.
    CHOICE-4: rule 1's rejection code is not named in the spec; chosen TOKEN_INVALID.
    """
    # rule 1
    if not (parent_held_by_delegator and parent_holder_id == delegator):
        return TOKEN_INVALID
    # rule 2
    if not child_scope_in_parent:
        return SCOPE_VIOLATION
    # rule 3 is a truncation, never a rejection
    # rule 4 is computed
    # rule 5
    if not parent_redelegatable:
        return NOT_REDELEGATABLE
    return OK


def truncate_child_not_after(now, ttl, parent_not_after):
    return min(now + ttl, parent_not_after)


def child_depth(parent_depth):
    return parent_depth + 1


# ------------------------------------------------- §3.2 step 1c (time window)
def window_ok(now, ts, clock_skew, max_request_age):
    """CHOICE-5: step 1c's formula `-clock_skew <= now - ts <= max_request_age`
    is taken as normative; the prose sentence `0 <= now - ts <= max_request_age`
    (line 316) is read as the clock_skew=0 special case."""
    return -clock_skew <= now - ts <= max_request_age


# ------------------------------------------------- §2.3 chain root (line 65)
def chain_root(token):
    if token["chain"]:
        return token["chain"][0]["parent_token_id"]
    return token["token_id"]
