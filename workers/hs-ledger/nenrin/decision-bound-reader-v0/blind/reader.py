#!/usr/bin/env python3
"""Blind clean-room reader for decision-bound-output-v1 records.

Written from the contract text only (docstring + code of decision_bound.py,
and jcs.py as the statement of which canonical form is meant). Nothing from
the fence is imported or executed. Python 3 standard library only.

Usage: python3 -I -B reader.py <vectors.json> <out.json>
"""
import hashlib
import json
import sys
from datetime import datetime, timezone

VERSION = "decision-bound-output-v1"


# ---------------------------------------------------------------- canonical JSON
# Own implementation of RFC 8785 for the value kinds these records use:
# objects, arrays, strings, booleans, null and integers. Non-integral numbers
# are refused rather than guessed (see GAPS.md).

def _esc(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_key(k):
    b = k.encode('utf-16-be', 'surrogatepass')
    return [int.from_bytes(b[i:i + 2], 'big') for i in range(0, len(b), 2)]


def canon(v):
    if v is None:
        return 'null'
    if v is True:
        return 'true'
    if v is False:
        return 'false'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 2 ** 53:
            return str(int(v))
        raise ValueError('non-integral number not supported by this reader: %r' % v)
    if isinstance(v, str):
        return _esc(v)
    if isinstance(v, list):
        return '[' + ','.join(canon(x) for x in v) + ']'
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise ValueError('non-string key')
        keys = sorted(v.keys(), key=_utf16_key)
        return '{' + ','.join(_esc(k) + ':' + canon(v[k]) for k in keys) + '}'
    raise ValueError('unsupported type %s' % type(v).__name__)


def sha256_ref(obj):
    return 'sha256:' + hashlib.sha256(canon(obj).encode('utf-8')).hexdigest()


# ---------------------------------------------------------------- checks

def chk(checks, name, recomputed, stated):
    checks[name] = {'recomputed': recomputed, 'stated': stated,
                    'equal': recomputed == stated}
    return recomputed == stated


def read_case(c):
    checks = {}
    notes = []
    cid = c.get('case_id', '?')

    content = c.get('content_sha256')
    pre = c.get('decision_preimage')
    stated_did = c.get('decision_id')
    stated_bound = c.get('decision_bound_output_hash')
    stated_legacy = c.get('legacy_output_hash')

    missing = [k for k, v in (('content_sha256', content), ('decision_preimage', pre),
                              ('decision_id', stated_did),
                              ('decision_bound_output_hash', stated_bound)) if v is None]
    if missing:
        notes.append('missing required field(s): ' + ', '.join(missing))

    # 1. decision_id = SHA-256(JCS(decision_preimage)), "sha256:" prefixed
    did_ok = False
    rec_did = None
    if isinstance(pre, dict):
        rec_did = sha256_ref(pre)
        did_ok = chk(checks, 'decision_id', rec_did, stated_did)
        listed = {'action_ref', 'policy_id', 'outcome', 'ts_ms'}
        extra = sorted(set(pre) - listed)
        absent = sorted(listed - set(pre))
        if extra:
            notes.append('decision_preimage carries fields beyond the four the docstring '
                         'names (action_ref, policy_id, outcome, ts_ms): %s; hashed as-is'
                         % ', '.join(extra))
        if absent:
            notes.append('decision_preimage lacks docstring-named field(s): %s'
                         % ', '.join(absent))

    # 2. bound output_hash = SHA-256(JCS({content_sha256, decision_id, version}))
    #    folded with the RECOMPUTED decision_id (the binding is to the decision's
    #    own content, not to whatever id string the record carries).
    bound_ok = False
    if isinstance(content, str) and rec_did is not None:
        bp = {'content_sha256': content, 'decision_id': rec_did, 'version': VERSION}
        rec_bound = sha256_ref(bp)
        bound_ok = chk(checks, 'decision_bound_output_hash', rec_bound, stated_bound)
        if not bound_ok:
            # diagnostics only: which other reading, if any, reproduces the value
            alts = {}
            if isinstance(stated_did, str) and stated_did != rec_did:
                alts['with_stated_decision_id'] = sha256_ref(
                    {'content_sha256': content, 'decision_id': stated_did, 'version': VERSION})
            alts['content_prefixed_sha256'] = sha256_ref(
                {'content_sha256': 'sha256:' + content, 'decision_id': rec_did,
                 'version': VERSION})
            alts['decision_id_bare_hex'] = sha256_ref(
                {'content_sha256': content, 'decision_id': rec_did.split(':', 1)[-1],
                 'version': VERSION})
            hits = [k for k, v in alts.items() if v == stated_bound]
            notes.append('bound hash alternative readings that match stated: %s'
                         % (hits or 'none'))

    # 3. legacy output_hash = "sha256:" + content_sha256 (recognition only)
    legacy_ok = None
    if isinstance(content, str) and stated_legacy is not None:
        legacy_ok = chk(checks, 'legacy_output_hash', 'sha256:' + content, stated_legacy)

    # 4. record-internal consistency (not defined by the contract; informational)
    src = c.get('source') or {}
    ar = src.get('approved_request') or {}
    if 'content_sha256' in ar and isinstance(content, str):
        chk(checks, 'info:source.approved_request.content_sha256', content,
            ar['content_sha256'])
    if isinstance(pre, dict) and isinstance(pre.get('policy_id'), str) \
            and 'execution_digest' in src and 'grant_profile' in src:
        chk(checks, 'info:policy_id_vs_grant_profile/execution_digest',
            '%s/%s' % (src['grant_profile'], src['execution_digest']), pre['policy_id'])
    if isinstance(pre, dict) and isinstance(pre.get('ts_ms'), int) \
            and isinstance(src.get('grant_issued_at_iso'), str):
        iso = datetime.fromtimestamp(pre['ts_ms'] / 1000, tz=timezone.utc) \
            .strftime('%Y-%m-%dT%H:%M:%SZ')
        chk(checks, 'info:ts_ms_as_iso_vs_grant_issued_at_iso', iso,
            src['grant_issued_at_iso'])

    # format sanity on content_sha256 (bytes themselves are not in the record)
    if isinstance(content, str):
        if not (len(content) == 64 and all(ch in '0123456789abcdef' for ch in content)):
            notes.append('content_sha256 is not 64 lowercase hex chars')
    notes.append('written content bytes are not in the record; content_sha256 is taken '
                 'as given, not recomputed')
    notes.append('decision_preimage is taken from the record itself; its authenticity '
                 '(separate channel) is outside this check, per the contract')
    if c.get('synthetic') is False:
        notes.append('record self-declares synthetic=false; not independently checkable')

    if did_ok and bound_ok:
        verdict = 'BOUND'
    elif rec_did is not None and did_ok and not bound_ok and legacy_ok:
        verdict = 'UNBOUND_LEGACY_ONLY'
    elif rec_did is not None and not did_ok:
        verdict = 'FAIL_DECISION_ID'
    else:
        verdict = 'FAIL_BINDING'

    info_bad = [k for k, v in checks.items() if k.startswith('info:') and not v['equal']]
    if info_bad:
        notes.append('informational cross-field mismatch(es): ' + ', '.join(info_bad))
    return cid, {'verdict': verdict, 'checks': checks, 'notes': notes}


def main(argv):
    if len(argv) != 3:
        print('usage: reader.py <vectors.json> <out.json>', file=sys.stderr)
        return 2
    with open(argv[1], 'r', encoding='utf-8') as f:
        data = json.load(f)
    cases = data.get('cases', []) if isinstance(data, dict) else data
    out = {}
    tally = {}
    m = mm = 0
    for c in cases:
        cid, res = read_case(c)
        out[cid] = res
        tally[res['verdict']] = tally.get(res['verdict'], 0) + 1
        for v in res['checks'].values():
            if v['equal']:
                m += 1
            else:
                mm += 1
        print('%s %s' % (cid, res['verdict']))
    with open(argv[2], 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write('\n')
    print('cases=%d %s checks_matched=%d checks_mismatched=%d' % (
        len(cases), ' '.join('%s=%d' % kv for kv in sorted(tally.items())), m, mm))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
