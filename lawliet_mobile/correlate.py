"""Transparent exact-entity pivots across imported evidence sources."""
import re
from collections import defaultdict
from urllib.parse import urlsplit, urlunsplit


def shared_entities(db, minimum=2, kind="all"):
    hits = defaultdict(dict)
    for row in db.execute("SELECT id,evidence_id,title,body FROM artifacts"):
        text = row["title"] + " " + row["body"]
        found = set()
        for value in re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE):
            value = value.rstrip(".,;!?)\u2026")
            try:
                url = urlsplit(value)
                if not url.hostname:
                    continue
                normalized = urlunsplit((url.scheme.lower(), url.netloc.lower(), url.path or "/", url.query, ""))
                found.add(("url", normalized))
                found.add(("domain", url.hostname.lower()))
            except ValueError:
                continue
        for value in re.findall(r"(?<!\w)\+?\d[\d ()-]{5,}\d(?!\w)", text):
            digits = re.sub(r"\D", "", value)
            if 7 <= len(digits) <= 15:
                found.add(("phone", ("+" if value.startswith("+") else "") + digits))
        for entity in found:
            if kind == "all" or kind == entity[0]:
                hits[entity][row["id"]] = row["evidence_id"]
    result = []
    for (entity_kind, value), occurrences in hits.items():
        sources = sorted(set(occurrences.values()))
        if len(sources) >= minimum:
            result.append({"kind": entity_kind, "value": value, "evidence_sources": len(sources),
                           "records": len(occurrences), "evidence_ids": sources, "record_ids": sorted(occurrences)})
    return sorted(result, key=lambda r: (-r["evidence_sources"], -r["records"], r["kind"], r["value"]))
