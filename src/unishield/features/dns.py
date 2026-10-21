"""
UniShield — DNS Feature Extractor

DNS metadata features for DGA and DNS-tunnelling detection. Works on query
names, query types and response codes only — no resolution or payload
decryption.

Two separate views:
    DGA        per client: registrable domains (e.g. "example.co.uk") whose
               main label looks machine-generated — rare letter pairs, high
               entropy, digits — and the NXDOMAIN share of its answers.
    Tunnelling per base domain: many unique, long, high-entropy subdomains
               (data encoded in the name) and TXT/NULL record use.

Labels are scored on their own, so a benign name such as
``img12.example.com`` is not treated as random just because the full query
string is long.

SECURITY CONSTRAINTS:
    - Read-only: operates on DNS metadata fields only.
    - No DNS resolution or lookups performed.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.schemas.flow import NormalisedFlow

# Most frequent English letter pairs; names made of these read as words.
COMMON_BIGRAMS = frozenset("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de
hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr
ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su
id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od
bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp
ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph
og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw
ju oa eq sy sl ps jo lf nv je nk kn gs dy hy ze ks xt bs ik dd cy rp sk xi oe oy ws lv dl rf eu dg wr
xa yi nm eb rb tm xc eh tc gy ja hn yp za gg ym sw lm cs ix xe oh lk dv lp ax ox uf dm iu sf bt ka yt
ek pm ya gt wl rh yl hs ah yc yn rw hm lw hl ae zi az lc py aj iq bb nh lr tn gm sn nr fy mn sb yr dn
zo yd lb wt lg ko np sr ky ln nw tf fs dh sd vy dj hw ao ml uk uy ez hb nb mc yb tp kh gd bm mr ku dt
hd aa df db ji kr xo cm zy
""".split())

# Public suffixes made of two labels (small built-in subset).
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.in", "ac.in", "gov.in", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "com.br", "com.cn", "com.sg", "co.nz", "co.za", "com.mx", "co.kr",
})

_TUNNEL_RECORD_TYPES = {"TXT", "NULL", "ANY", "CNAME", "MX"}


def char_entropy(s: str) -> float:
    """Shannon entropy (bits per character)."""
    if not s:
        return 0.0
    counts = Counter(s.lower())
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_domain(query: str) -> tuple[str, str, str]:
    """(subdomain part, main label, registrable domain) for a query name."""
    labels = [l for l in query.lower().strip(".").split(".") if l]
    if len(labels) < 2:
        name = labels[0] if labels else ""
        return "", name, name
    suffix_len = 2 if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES and len(labels) >= 3 else 1
    main = labels[-suffix_len - 1]
    registrable = ".".join(labels[-suffix_len - 1:])
    sub = ".".join(labels[:-suffix_len - 1])
    return sub, main, registrable


def bigram_rarity(label: str) -> float:
    """Share of letter pairs in ``label`` that are not common English pairs (0 = word-like)."""
    letters = "".join(c for c in label.lower() if c.isalpha())
    pairs = [letters[i:i + 2] for i in range(len(letters) - 1)]
    if not pairs:
        return 1.0 if any(c.isdigit() for c in label) else 0.0
    return sum(1 for p in pairs if p not in COMMON_BIGRAMS) / len(pairs)


def _max_consonant_run(label: str) -> int:
    best = run = 0
    for c in label.lower():
        run = run + 1 if c.isalpha() and c not in "aeiouy" else 0
        best = max(best, run)
    return best


def looks_generated(label: str, min_length: int = 8) -> bool:
    """
    Heuristic for a machine-generated label (>= ``min_length`` characters): many
    rare letter pairs, or some rare pairs plus digits mixed in at high entropy,
    or a run of 5+ consonants. On random 10–16 character names it flags about
    70%; individual benign names can also match (e.g. "hdfcbank"), which is why
    the DGA rule requires many such domains from one client.
    """
    if len(label) < min_length:
        return False
    digits = sum(c.isdigit() for c in label) / len(label)
    rarity = bigram_rarity(label)
    return (
        rarity >= 0.4
        or (char_entropy(label) >= 3.3 and digits >= 0.2 and rarity >= 0.25)
        or (_max_consonant_run(label) >= 5 and rarity >= 0.25)
    )


def _consonant_ratio(s: str) -> float:
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c not in "aeiou") / len(alpha)


class DNSFeatureExtractor(BaseFeatureExtractor):
    """Extract DGA (per client) and tunnelling (per base domain) features."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def feature_names(self) -> list[str]:
        return [
            "dns_query_count",
            "unique_domains",
            "avg_query_length",
            "max_query_length",
            "avg_domain_entropy",
            "max_domain_entropy",
            "avg_subdomain_depth",
            "max_subdomain_depth",
            "nxdomain_ratio",
            "txt_record_ratio",
            "unique_subdomain_ratio",
            "avg_consonant_ratio",
            "high_entropy_domains",
            "long_query_domains",
            "dga_candidates",
            "tunnel_candidates",
        ]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        dns = [f for f in flows if f.dns_query]
        if not dns:
            empty: dict[str, Any] = {name: 0 for name in self.feature_names}
            empty.update(dga_candidates=[], tunnel_candidates=[])
            return empty

        queries = [f.dns_query.lower().strip(".") for f in dns]
        parts = [split_domain(q) for q in queries]
        lengths = [len(q) for q in queries]
        main_entropy = [char_entropy(main) for _, main, _ in parts]
        with_rcode = [f for f in dns if f.dns_rcode]
        nx = [f for f in with_rcode if f.dns_rcode.upper() == "NXDOMAIN"]

        return {
            "dns_query_count": len(dns),
            "unique_domains": len(set(queries)),
            "avg_query_length": round(sum(lengths) / len(lengths), 2),
            "max_query_length": max(lengths),
            "avg_domain_entropy": round(sum(main_entropy) / len(main_entropy), 4),
            "max_domain_entropy": round(max(main_entropy), 4),
            "avg_subdomain_depth": round(sum(q.count(".") + 1 for q in queries) / len(queries), 2),
            "max_subdomain_depth": max(q.count(".") + 1 for q in queries),
            "nxdomain_ratio": round(len(nx) / len(with_rcode), 4) if with_rcode else 0.0,
            "txt_record_ratio": round(sum(1 for f in dns if (f.dns_record_type or "").upper() == "TXT") / len(dns), 4),
            "unique_subdomain_ratio": round(len({s for s, _, _ in parts if s}) / len(dns), 4),
            "avg_consonant_ratio": round(sum(_consonant_ratio(m) for _, m, _ in parts) / len(parts), 4),
            "high_entropy_domains": sum(1 for _, main, _ in parts if looks_generated(main)),
            "long_query_domains": sum(1 for l in lengths if l > 50),
            "dga_candidates": self._dga_candidates(dns, parts),
            "tunnel_candidates": self._tunnel_candidates(dns, parts),
        }

    @staticmethod
    def _dga_candidates(dns: list[NormalisedFlow], parts: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
        by_client: dict[str, dict] = defaultdict(lambda: {"domains": {}, "answers": 0, "nx": 0, "queries": 0})
        for f, (_, main, registrable) in zip(dns, parts):
            c = by_client[f.source_ip]
            c["queries"] += 1
            c["domains"][registrable] = main
            c["resolver"] = f.destination_ip
            if f.dns_rcode:
                c["answers"] += 1
                c["nx"] += f.dns_rcode.upper() == "NXDOMAIN"
        out = []
        for client, c in by_client.items():
            generated = [d for d, main in c["domains"].items() if looks_generated(main)]
            if not generated:
                continue
            out.append({
                "source_ip": client,
                "resolver_ip": c["resolver"],
                "queries": c["queries"],
                "distinct_domains": len(c["domains"]),
                "generated_looking_domains": len(generated),
                "generated_share": round(len(generated) / len(c["domains"]), 4),
                "nxdomain_ratio": round(c["nx"] / c["answers"], 4) if c["answers"] else None,
                "examples": sorted(generated)[:5],
            })
        out.sort(key=lambda x: x["generated_looking_domains"], reverse=True)
        return out[:10]

    @staticmethod
    def _tunnel_candidates(dns: list[NormalisedFlow], parts: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
        by_base: dict[str, dict] = defaultdict(lambda: {"subs": [], "types": Counter(), "clients": set()})
        for f, (sub, _, registrable) in zip(dns, parts):
            b = by_base[registrable]
            b["subs"].append(sub)
            b["types"][(f.dns_record_type or "").upper()] += 1
            b["clients"].add(f.source_ip)
        out = []
        for base, b in by_base.items():
            subs = [s for s in b["subs"] if s]
            if len(subs) < 5:
                continue
            sub_lengths = [len(s) for s in subs]
            entropies = [char_entropy(s.replace(".", "")) for s in subs]
            queries = len(b["subs"])
            out.append({
                "base_domain": base,
                "queries": queries,
                "unique_subdomains": len(set(subs)),
                "unique_subdomain_ratio": round(len(set(subs)) / queries, 4),
                "avg_subdomain_length": round(sum(sub_lengths) / len(sub_lengths), 2),
                "max_subdomain_length": max(sub_lengths),
                "avg_subdomain_entropy": round(sum(entropies) / len(entropies), 4),
                "tunnel_record_ratio": round(sum(b["types"][t] for t in _TUNNEL_RECORD_TYPES) / queries, 4),
                "txt_ratio": round(b["types"]["TXT"] / queries, 4),
                "encoded_bytes": sum(sub_lengths),
                "clients": sorted(b["clients"])[:5],
            })
        out.sort(key=lambda x: x["encoded_bytes"], reverse=True)
        return out[:10]
