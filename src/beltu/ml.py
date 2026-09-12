from __future__ import annotations

from typing import Any

from beltu.core.models import Finding


def semantic_signal(findings: list[Finding]) -> dict[str, Any]:
    """Optional scikit-learn signal for duplicate/anomaly awareness, never proof of a vulnerability."""
    if len(findings) < 2:
        return {"available": False, "reason": "need at least two findings"}
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except Exception as exc:
        return {"available": False, "reason": f"scikit-learn unavailable: {exc}"}

    texts = [f"{f.engine} {f.category} {f.title} {f.description}" for f in findings]
    matrix = TfidfVectorizer(ngram_range=(1, 2), min_df=1).fit_transform(texts)
    sim = cosine_similarity(matrix)
    duplicate_pairs: list[dict[str, Any]] = []
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if sim[i, j] >= 0.92:
                duplicate_pairs.append({"a": findings[i].id, "b": findings[j].id, "similarity": round(float(sim[i, j]), 4)})
    mean_similarity = float(sim.sum() - len(findings)) / max(len(findings) * (len(findings) - 1), 1)
    return {
        "available": True,
        "mean_similarity": round(mean_similarity, 4),
        "duplicate_pairs": duplicate_pairs[:100],
        "finding_count": len(findings),
        "purpose": "duplicate/anomaly signal only; not exploit confirmation",
    }
