#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate vectors/vectors_v0_1.json for the MUSUBI companion for cA2A, profile v0.1 (the witnessed lane).

Same keys, credentials and test chain as gen_vectors.py. Each vector mines its own regtest headers so a
witness acknowledgement, a receipt's seen block and the checkpoint anchor sit at chosen heights. Running
this twice gives the same bytes.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import gen_vectors as G      # noqa: E402  (keys, credentials, items, log builder; also fixes the JCS digest)
import companion_v0 as C     # noqa: E402
import companion_v0_1 as C1  # noqa: E402

v11 = G.v11
BLOCK0, SPACING = 1700000000, 600

# the test chain stamps every block 1700000000; here each block is ten minutes after the one before, so a
# checkpoint's as_of can fall before or after a given block. Block 95 keeps its time and so its hash.
_mine0 = v11._mine


def _mine_spaced(prev_hash, merkle, bits=v11.REGTEST_BITS, t=BLOCK0, salt=0):
    h = (salt - len(G.LABEL)) // 7
    return _mine0(prev_hash, merkle, bits, BLOCK0 + SPACING * (h - 95), salt)


v11._mine = _mine_spaced


def btime(h):
    return BLOCK0 + SPACING * (h - 95)


W1, W1_PUB = G.key("witness-1")
W2, W2_PUB = G.key("witness-2")
W3, W3_PUB = G.key("witness-3")
WITNESSES = sorted([W1_PUB, W2_PUB, W3_PUB])
T0 = G.T0


def ack(k, pub, item, seen, log_id=G.LOG_ID, digest=None):
    return C.sign({"type": C1.T_ACK, "log_id": log_id, "witness": pub,
                   "item_sha256": digest or C1.item_sha256(item), "seen_block": seen}, k)


class Sc:
    """One regtest chain from height 95, mined step by step."""
    def __init__(self):
        self.ch = v11._Chain(95, "00" * 32, G.LABEL)
        self.ch.block()
        assert self.ch.hashes[95] == G.SEEN["hash"]

    def tip(self):
        h = max(self.ch.hashes)
        return {"height": h, "hash": self.ch.hashes[h]}

    def mine(self, recs=()):
        return self.ch.block(list(recs))

    def witness(self, item, signers, seen=None, **kw):
        seen = seen or self.tip()
        return {"item": item, "acks": self.mine([ack(k, p, item, seen, **kw) for k, p in signers])}

    def finish(self, items, witnessed=(), depth=6, trust_over=None, after_cp=None, tail=None, mutate=None,
               as_of=G.AS_OF):
        entries, cp = G.build_log(items, as_of=as_of)
        [cp] = self.mine([cp])
        witnessed = list(witnessed)
        if after_cp:
            witnessed += after_cp(self)
        while max(self.ch.hashes) - cp["anchor"]["height"] + 1 < depth:
            self.mine()
        if tail:
            witnessed += tail(self)
        lb = {"kind": "bitcoin_block", "height": 95, "hash": self.ch.hashes[95]}
        tr = G.trust(lb)
        tr.update({"witnesses": WITNESSES, "witness_threshold": 2, "max_merge_blocks": 3})
        if trust_over:
            trust_over(tr)
        b = {"profile": C1.PROFILE, "trust": tr, "view": self.ch.view(),
             "log": {"entries": entries, "checkpoint": cp}, "chains": [], "witnessed": witnessed}
        b = json.loads(C.jcs(b))
        if mutate:
            mutate(b)
        return b


VECTORS = []


def vec(vid, desc, b):
    VECTORS.append({"id": vid, "description": desc, "bundle": b, "expected": json.loads(C.jcs(C1.settle(b)))})


def rev_c1(issued_at=T0, k=None, pub=None):
    return G.revocation(G.C1, k or G.A, pub or G.A_PUB, issued_at)


TWO = [(W1, W1_PUB), (W2, W2_PUB)]


def main():
    RS1, RS2 = G.RS1, G.RS2

    # the case v0 could not touch: the operator never logs the revocation
    s = Sc()
    w = s.witness(rev_c1(), TWO)                                   # acks anchored at 96
    s.mine()                                                       # 97
    vec("WV01_refused_revocation_still_applies",
        "the operator never logs the delegator's revocation; two trusted witnesses acknowledged it and the "
        "acknowledgements were anchored before the block the responder says it had seen, so the execution "
        "is after a published revocation",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    w = s.witness(rev_c1(), TWO)
    s.mine()
    seen = s.tip()
    for _ in range(3):
        s.mine()                                                   # the checkpoint is anchored at 101
    vec("WV02_omission_is_provable",
        "the same refusal, and the operator signs a checkpoint whose as_of is past the time of the block "
        "max_merge_blocks after the witnessing, without carrying the revocation: the witnesses' and the "
        "operator's signatures show it",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], [w], as_of=btime(99) + 1))

    s = Sc()
    r = rev_c1()
    w = s.witness(r, TWO)
    s.mine()
    seen = s.tip()
    for _ in range(3):
        s.mine()
    vec("WV03_carried_revocation_is_no_finding",
        "the operator does carry the witnessed revocation: no finding, and its log seq is reported",
        s.finish([G.policy(5), G.use(RS1), r, G.receipt(RS1, seen=seen)], [w], as_of=btime(99) + 1))

    s = Sc()
    w = s.witness(rev_c1(), [(W1, W1_PUB)])
    s.mine()
    vec("WV04_one_witness_is_not_enough",
        "the threshold is two; one acknowledgement does not publish anything",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    w = s.witness(rev_c1(), [(W1, W1_PUB), (G.Z, G.Z_PUB)])
    s.mine()
    vec("WV05_untrusted_witness_does_not_count",
        "a second acknowledgement from a key the relying party does not trust",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    r = rev_c1()
    w = s.witness(r, [(W1, W1_PUB), (W1, W1_PUB)], seen=G.SEEN)
    s.mine()
    w2 = {"item": r, "acks": w["acks"] + s.mine([ack(W1, W1_PUB, r, s.tip())])}
    s.mine()
    vec("WV06_one_witness_counts_once",
        "three acknowledgements, all from the same witness, are one witness",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w2]))

    s = Sc()
    w = s.witness(rev_c1(), TWO)
    s.mine()

    def op_witness(tr):
        tr["witnesses"] = sorted([W1_PUB, G.O_PUB])
    vec("WV07_operator_cannot_witness_itself", "a trust configuration listing the operator as a witness is refused",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w], trust_over=op_witness))

    s = Sc()
    r = rev_c1()
    other = rev_c1(issued_at=T0 + 1)
    w = {"item": r, "acks": s.mine([ack(W1, W1_PUB, r, G.SEEN),
                                    ack(W2, W2_PUB, other, G.SEEN, digest=C1.item_sha256(other))])}
    s.mine()
    vec("WV08_ack_for_another_item",
        "one of the two acknowledgements is for a different revocation and is not counted",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    r = rev_c1()
    w = {"item": r, "acks": s.mine([ack(W1, W1_PUB, r, G.SEEN), ack(W2, W2_PUB, r, G.SEEN, log_id="other:log")])}
    s.mine()
    vec("WV09_ack_for_another_log",
        "an acknowledgement made for another log is not reused for this one",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    w = s.witness(rev_c1(), TWO)
    s.mine()

    def move_anchor(b):
        a = b["witnessed"][0]["acks"][1]["anchor"]
        a["height"] = 97
        a["block_hash"] = b["view"]["headers"][2]["hex"] and \
            v11.header_hash(bytes.fromhex(b["view"]["headers"][2]["hex"]))
    vec("WV10_ack_anchor_moved",
        "an acknowledgement's anchor is moved to a later block it is not in: the proof fails there, so only "
        "one anchor counts and the restriction has no upper bound; its two signatures still make it unresolved",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w], mutate=move_anchor))

    s = Sc()
    r = rev_c1()
    w = {"item": r, "acks": s.mine([ack(W1, W1_PUB, r, G.SEEN),
                                    ack(W2, W2_PUB, r, {"height": 95, "hash": "11" * 32})])}
    s.mine()
    vec("WV11_ack_seen_block_not_in_view",
        "an acknowledgement names a block the view does not hold: it gives no lower bound, but its anchor still "
        "shows the witness had signed by 96",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    w = s.witness(rev_c1(), TWO, seen=G.SEEN)                      # witnessed at 96, after seeing 95
    s.mine()
    vec("WV12_stale_seen_block_buys_nothing",
        "the responder names block 95, older than the witnessing; it cannot be shown to have executed after "
        "the revocation, nor before it: order_unresolved, not within",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=G.SEEN)], [w]))

    def late_witness(issued_at):
        def f(sc):
            sc.mine()                                              # the witnesses see a block after the anchor
            return [sc.witness(rev_c1(issued_at=issued_at), TWO)]
        return f
    s = Sc()
    s.mine()
    seen = s.tip()
    vec("WV13_revocation_witnessed_after_the_fact",
        "the revocation reaches the witnesses only after the receipt was anchored, and is dated after the "
        "execution: it does not judge that execution",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], after_cp=late_witness(T0 + 900),
                 depth=8))
    s = Sc()
    s.mine()
    seen = s.tip()
    vec("WV14_backdated_and_witnessed_late",
        "the same, but dated before the execution: cA2A's audit sees it, the blocks say it was published "
        "late, so late_revocation_only",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], after_cp=late_witness(T0),
                 depth=8))

    s = Sc()
    w = s.witness(G.policy(1), TWO)
    s.mine()
    seen = s.tip()
    vec("WV15_refused_use_limit_still_applies",
        "the operator never logs the issuer's single-use limit; witnessed before both executions, the second "
        "use exceeds it",
        s.finish([G.use(RS1), G.receipt(RS1, seen=seen), G.use(RS2), G.receipt(RS2, seen=seen)], [w]))

    s = Sc()
    w = s.witness(G.policy(1, G.B, G.B_PUB), TWO)
    s.mine()
    seen = s.tip()
    vec("WV16_witnessed_policy_by_non_issuer",
        "a witnessed limit signed by the leaf's subject is accepted by the lane and limits nothing",
        s.finish([G.use(RS1), G.receipt(RS1, seen=seen), G.use(RS2), G.receipt(RS2, seen=seen)], [w]))

    s = Sc()
    w = s.witness(G.use(RS2), TWO)
    s.mine()
    vec("WV17_only_restrictions_go_around_the_operator",
        "a credential use sent to the witnesses is rejected; uses and receipts need the operator's sequence",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    w = s.witness(rev_c1(k=G.B, pub=G.B_PUB), TWO)
    s.mine()
    vec("WV18_witnessed_revocation_without_authority",
        "the leaf's own subject revokes it through the witnesses; cA2A gives it no authority",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    w = s.witness(rev_c1(), TWO)
    s.mine()

    def no_lane(tr):
        for k in ("witnesses", "witness_threshold", "max_merge_blocks"):
            del tr[k]
    vec("WV19_no_witnesses_trusted",
        "witnessed records but no witnesses in the trust configuration: each is rejected and the rest settles",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w], trust_over=no_lane))

    s = Sc()

    def half_lane(tr):
        del tr["witness_threshold"]
    vec("WV20_incomplete_lane_is_refused", "witnesses without a threshold is a malformed trust configuration",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], trust_over=half_lane))

    s = Sc()
    s.mine()
    seen = s.tip()
    vec("WV21_ack_anchor_too_shallow",
        "acknowledgements anchored in the last block of the view have fewer confirmations than required",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)],
                 tail=lambda sc: [sc.witness(rev_c1(), TWO)]))

    s = Sc()
    w = s.witness(rev_c1(issued_at=T0 + C.TIME_SLACK + 9000), TWO)
    s.mine()
    vec("WV22_revocation_dated_after_witnessing",
        "a witnessed revocation dated hours after its witnessing block is kept, flagged, and in force by block "
        "order; cA2A's audit by issued_at is reported beside it",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [w]))

    s = Sc()
    r = rev_c1()
    late = {"item": r, "acks": []}
    s.mine()
    early = s.witness(r, TWO)                                      # 97
    s.mine()
    late["acks"] = s.mine([ack(W1, W1_PUB, r, s.tip()), ack(W3, W3_PUB, r, s.tip())])  # 99
    s.mine()
    vec("WV23_the_earliest_witnessing_counts",
        "the same revocation witnessed twice; the earlier publication height is the one used",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [late, early], as_of=btime(100)))

    s = Sc()
    w = s.witness(G.policy(1), TWO, seen=G.SEEN)
    s.mine()
    vec("WV24_unresolved_use_limit",
        "a witnessed single-use limit whose order against the second execution cannot be fixed by blocks",
        s.finish([G.use(RS1), G.receipt(RS1, seen=G.SEEN), G.use(RS2), G.receipt(RS2, seen=G.SEEN)], [w]))

    s = Sc()
    r = rev_c1()
    acks = s.mine([ack(W1, W1_PUB, r, G.SEEN), ack(W2, W2_PUB, r, G.SEEN)])
    acks[1]["seen_block"] = s.tip()                                # changed after signing
    s.mine()
    vec("WV25_ack_altered_after_signing",
        "an acknowledgement's seen block is changed after the witness signed: its signature fails",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [{"item": r, "acks": acks}]))

    s = Sc()
    r = rev_c1()
    part1 = {"item": r, "acks": s.mine([ack(W1, W1_PUB, r, G.SEEN)])}          # 96
    part2 = {"item": r, "acks": s.mine([ack(W2, W2_PUB, r, s.tip())])}         # 97
    s.mine()
    vec("WV26_acks_pool_across_records",
        "one acknowledgement in each of two records for the same revocation: together they reach the "
        "threshold, published at the later of the two",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [part1, part2]))

    s = Sc()
    s.mine()
    seen = s.tip()                                                 # 96; the checkpoint is anchored at 97

    def staggered(sc):
        r = rev_c1()
        first = [ack(W1, W1_PUB, r, G.SEEN), ack(W2, W2_PUB, r, G.SEEN)]   # signed early, anchored late
        sc.mine()                                                  # 98
        second = sc.mine([ack(W1, W1_PUB, r, sc.tip()), ack(W2, W2_PUB, r, sc.tip())])   # 99, saw 98
        return [{"item": r, "acks": second + sc.mine(first)}]      # 100
    vec("WV27_a_later_ack_does_not_hide_an_earlier_one",
        "each witness signed once after block 95 (anchored at 100) and again after 98 (anchored at 99); "
        "publication is bounded by 99 above and 95 below, so against a receipt anchored at 97 the order is "
        "unresolved, not after",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], after_cp=staggered, depth=9))

    s = Sc()
    w = s.witness(rev_c1(), TWO)                                   # published at 96
    s.mine()
    seen = s.tip()
    s.mine()                                                       # the checkpoint is anchored at 99 = 96 + 3
    vec("WV28_merge_delay_boundary",
        "a checkpoint whose as_of equals the time of the block max_merge_blocks after the witnessing must "
        "carry the revocation; one second earlier it need not",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], [w], as_of=btime(99)))
    s = Sc()
    w = s.witness(rev_c1(), TWO)
    s.mine()
    seen = s.tip()
    s.mine()
    vec("WV29_one_second_before_the_delay",
        "the same checkpoint with as_of one second before that block's time: no finding",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], [w], as_of=btime(99) - 1))

    # third review, 2026-10-18: the anchor height is not when the operator signed
    s = Sc()
    s.mine()                                                       # 96
    seen = s.tip()
    entries, cp = G.build_log([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)])
    s.mine([cp])                                                   # first anchored at 97
    w = s.witness(rev_c1(issued_at=T0 + 900), TWO)                 # witnessed at 98, due at 101
    for _ in range(4):
        s.mine()                                                   # 99 to 102
    [cp_late] = s.mine([cp])                                       # the same signed checkpoint, anchored at 103
    for _ in range(5):
        s.mine()
    lb = {"kind": "bitcoin_block", "height": 95, "hash": s.ch.hashes[95]}
    tr = G.trust(lb)
    tr.update({"witnesses": WITNESSES, "witness_threshold": 2, "max_merge_blocks": 3})
    vec("WV30_reanchoring_does_not_frame_the_operator",
        "a checkpoint signed before the revocation existed and anchored again after the delay: its as_of is "
        "before the due block's time, so no finding; the receipt's order is unresolved",
        json.loads(C.jcs({"profile": C1.PROFILE, "trust": tr, "view": s.ch.view(),
                          "log": {"entries": entries, "checkpoint": cp_late}, "chains": [], "witnessed": [w]})))

    # third review: the lower bound comes from the signature and the seen block alone
    s = Sc()
    r = rev_c1(issued_at=T0 + 900)
    rec1 = {"item": r, "acks": s.mine([ack(W1, W1_PUB, r, G.SEEN)])}          # W1: saw 95, anchored 96
    seen = s.tip()                                                             # the receipt saw 96

    def slow(sc):
        sc.mine()                                                              # 98
        rec2 = {"item": r, "acks": sc.mine([ack(W2, W2_PUB, r, sc.tip())])}   # W2: saw 98, anchored 99
        return [rec2]
    w3 = ack(W3, W3_PUB, r, G.SEEN)                                            # W3: saw 95, anchored only at the tip
    vec("WV31_a_shallow_ack_still_lowers_the_bound",
        "three honest witnesses; the third's acknowledgement is anchored too shallow to count upward, but it "
        "signed after block 95, so the revocation may have been public before the receipt: unresolved",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], [rec1], after_cp=slow,
                 tail=lambda sc: [{"item": r, "acks": sc.mine([w3])}], depth=8))

    s = Sc()
    r = rev_c1(issued_at=T0 + 900)
    unanchored = [ack(W1, W1_PUB, r, G.SEEN), ack(W2, W2_PUB, r, G.SEEN)]
    s.mine()
    seen = s.tip()
    vec("WV32_signed_but_unanchored_is_never_before",
        "two witnesses signed but nothing is anchored: the restriction exists with no upper bound, so it is "
        "unresolved against this receipt and no omission can be charged to the operator",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], [{"item": r, "acks": unanchored}],
                 as_of=btime(102)))

    s = Sc()
    r = rev_c1()
    one = s.mine([ack(W1, W1_PUB, r, G.SEEN)])
    s.mine()
    copies = [one[0]] + [dict(one[0], anchor=dict(one[0]["anchor"], height=99)) for _ in range(5)]
    vec("WV33_identical_copies_are_checked_once",
        "the same acknowledgement bytes repeated are checked once; a copy with a different anchor is checked "
        "on its own, and here its anchor fails",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [{"item": r, "acks": copies}]))

    # fourth review, 2026-10-18: order of copies, a signature that is not a string, a seen block the view cannot
    # check, and a checkpoint anchored again later
    s = Sc()
    r = rev_c1()
    signed = [ack(W1, W1_PUB, r, G.SEEN), ack(W2, W2_PUB, r, G.SEEN)]
    anchored = s.mine(signed)                                      # 96
    s.mine()
    seen = s.tip()
    for _ in range(2):
        s.mine()
    vec("WV34_an_unanchored_copy_first_hides_nothing",
        "the witnesses' own unanchored copies come before the calendar's anchored copies of the same "
        "acknowledgements: both are checked, the restriction is published at 96 and the omission is reported",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)],
                 [{"item": r, "acks": signed + anchored}], as_of=btime(99) + 1))

    s = Sc()
    r = rev_c1()
    acks = s.mine([ack(W1, W1_PUB, r, G.SEEN), ack(W2, W2_PUB, r, G.SEEN)])
    s.mine()
    junk = [dict(acks[0], signature=[]), dict(acks[0], signature={"a": 1})]
    vec("WV35_a_signature_that_is_not_a_string",
        "two acknowledgements whose signature is a list or an object are rejected by name and the rest settles",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [{"item": r, "acks": junk + acks}]))

    s = Sc()
    r = rev_c1()
    below = {"height": 94, "hash": "22" * 32}                      # below the view's lower bound
    acks = s.mine([ack(W1, W1_PUB, r, below), ack(W2, W2_PUB, r, below)])
    s.mine()
    vec("WV36_unverifiable_seen_block_keeps_the_anchor",
        "both witnesses name a block below the view (an older lower bound, or a reorg): no lower bound, but "
        "their anchors still show they had signed by 96, which is before the receipt's seen block",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=s.tip())], [{"item": r, "acks": acks}]))

    s = Sc()
    s.mine()
    seen = s.tip()                                                 # 96
    entries, cp = G.build_log([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)])
    [cp_first] = s.mine([cp])                                      # 97
    s.mine()
    s.mine()
    w = s.witness(rev_c1(issued_at=T0 + 900), TWO)                 # witnessed at 100, saw 99
    for _ in range(4):
        s.mine()
    [cp_late] = s.mine([cp])                                       # the same checkpoint anchored again at 105
    for _ in range(6):
        s.mine()
    lb = {"kind": "bitcoin_block", "height": 95, "hash": s.ch.hashes[95]}
    tr = G.trust(lb)
    tr.update({"witnesses": WITNESSES, "witness_threshold": 2, "max_merge_blocks": 3})
    vec("WV37_the_earliest_checkpoint_anchor_counts",
        "the bundle carries the re-anchored checkpoint and, under extra_anchors, its first anchor at 97: the "
        "receipt existed by 97, the revocation was witnessed after 99, so the order is after and the receipt "
        "is within; without the first anchor it would be unresolved",
        json.loads(C.jcs({"profile": C1.PROFILE, "trust": tr, "view": s.ch.view(),
                          "log": {"entries": entries, "checkpoint": cp_late, "extra_anchors": [cp_first["anchor"]]},
                          "chains": [], "witnessed": [w]})))

    s = Sc()
    w = s.witness(rev_c1(), TWO)                                   # 96, due at 99
    s.mine()
    seen = s.tip()
    vec("WV38_due_block_beyond_the_view",
        "the view ends before the due block: the omission check is reported as not possible, not as clean",
        s.finish([G.policy(5), G.use(RS1), G.receipt(RS1, seen=seen)], [w], depth=1,
                 trust_over=lambda tr: tr.__setitem__("min_depth", 1), as_of=btime(99) + 1))

    # a lone surrogate cannot be written into a JCS vector file; it is checked by selftest_extra() instead

    out = {"profile": C1.PROFILE,
           "note": "credentials and revocations signed by ca2a_runtime; headers are regtest difficulty",
           "vectors": VECTORS}
    with open(os.path.join(HERE, "vectors", "vectors_v0_1.json"), "wb") as f:
        f.write(C.jcs(out))
    for v in VECTORS:
        e = v["expected"]
        if "refused" in e:
            print(v["id"], "REFUSED", e["refused"])
            continue
        if not e["log"]["verified"]:
            print(v["id"], "LOG", e["log"]["problem"])
            continue
        rs_ = ["%s:%s%s" % (r["seq"], r["disposition"], r.get("reasons") and str(r["reasons"]) or "")
               for r in e["receipts"]]
        print(v["id"], rs_, "W", [(x["published_height"], x["earliest_height"], len(x["signers"]),
                                   len(x["anchored"]), x["in_log_seq"], x.get("omission_check")) for x in e["witnessed"]],
              e["witnessed_rejected"] or "", e["operator_findings"] or "", e["items_flagged"] or "")


def selftest_extra():
    """Inputs no vector file can hold: a lone surrogate is refused with a code, never raised."""
    s = Sc()
    s.mine()
    b = s.finish([G.policy(5), G.use(G.RS1), G.receipt(G.RS1, seen=s.tip())])
    b["requests"] = [dict(G.REQ1, occurrence_id="\ud800")]
    r = C1.settle(b)
    assert r.get("refused") == "lone_surrogate", r
    b["requests"] = []
    b["chains"] = [[dict(G.wire(G.C0), credential_id="\udfff")]]
    r = C1.settle(b)
    assert r.get("refused") == "lone_surrogate", r
    print("extra: lone surrogates refused")


if __name__ == "__main__":
    main()
    selftest_extra()
