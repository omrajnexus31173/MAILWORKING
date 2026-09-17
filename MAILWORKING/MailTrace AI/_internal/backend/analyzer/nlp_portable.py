"""
Dependency-free inference for the MailTrace phishing classifier.

The model is a scikit-learn TfidfVectorizer(word 1-2 grams, sublinear tf, l2 norm) +
LogisticRegression, exported by scripts/train_model.py to a plain (gzipped) JSON file
containing the vocabulary, idf vector, coefficients and intercept.

This module re-implements the exact sklearn transform in pure Python, so the runtime
needs neither scikit-learn nor numpy and the model file works with any Python version
(no pickle, no InconsistentVersionWarning). Numerical equality with the sklearn pipeline
is asserted at export time on the hold-out set.
"""
import os, re, json, gzip, math, unicodedata
from typing import Dict, Any, List, Tuple, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTABLE_PATH = os.path.join(ROOT, "models", "phish_nlp_portable.json.gz")


class PortableTfidfLR:
    def __init__(self, d: Dict[str, Any]):
        if d.get("format") != "mailtrace-tfidf-lr-v1":
            raise ValueError("unknown portable model format")
        self.vocab: Dict[str, int] = d["vocab"]
        self.idf: List[float] = d["idf"]
        self.coef: List[float] = d["coef"]
        self.intercept = float(d["intercept"])
        p = d.get("params", {})
        self.ngram_min, self.ngram_max = p.get("ngram_range", [1, 2])
        self.token_re = re.compile(p.get("token_pattern", r"(?u)\b\w\w+\b"))
        self.lowercase = bool(p.get("lowercase", True))
        self.strip_accents = p.get("strip_accents") == "unicode"
        self.sublinear_tf = bool(p.get("sublinear_tf", False))
        self.norm = p.get("norm", "l2")
        self.meta: Dict[str, Any] = d.get("meta", {})
        self.n_features = len(self.idf)
        self._inv: Optional[List[str]] = None

    # ---- sklearn-equivalent analyzer -------------------------------------
    @staticmethod
    def _strip_accents_unicode(s: str) -> str:
        try:
            s.encode("ASCII", errors="strict")
            return s
        except UnicodeEncodeError:
            n = unicodedata.normalize("NFKD", s)
            return "".join(c for c in n if not unicodedata.combining(c))

    def analyze(self, doc: str) -> List[str]:
        if self.lowercase:
            doc = doc.lower()
        if self.strip_accents:
            doc = self._strip_accents_unicode(doc)
        toks = self.token_re.findall(doc)
        min_n, max_n = self.ngram_min, self.ngram_max
        if max_n == 1:
            return toks
        out = list(toks) if min_n == 1 else []
        if min_n == 1:
            min_n = 2
        n_orig = len(toks)
        for n in range(min_n, min(max_n + 1, n_orig + 1)):
            for i in range(n_orig - n + 1):
                out.append(" ".join(toks[i:i + n]))
        return out

    # ---- tf-idf --------------------------------------------------------
    def vectorize(self, doc: str) -> Dict[int, float]:
        counts: Dict[int, int] = {}
        vocab = self.vocab
        for t in self.analyze(doc):
            j = vocab.get(t)
            if j is not None:
                counts[j] = counts.get(j, 0) + 1
        if not counts:
            return {}
        vec: Dict[int, float] = {}
        idf = self.idf
        for j, c in counts.items():
            tf = (math.log(c) + 1.0) if self.sublinear_tf else float(c)
            vec[j] = tf * idf[j]
        if self.norm == "l2":
            nrm = math.sqrt(sum(v * v for v in vec.values()))
            if nrm > 0:
                vec = {j: v / nrm for j, v in vec.items()}
        return vec

    # ---- logistic regression -------------------------------------------
    @staticmethod
    def _sigmoid(z: float) -> float:
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def decision(self, vec: Dict[int, float]) -> float:
        coef = self.coef
        return self.intercept + sum(v * coef[j] for j, v in vec.items())

    def predict_proba(self, doc: str) -> float:
        """Probability that `doc` is phishing (class 1)."""
        return self._sigmoid(self.decision(self.vectorize(doc)))

    def explain(self, doc: str, k_pos: int = 10, k_neg: int = 6) -> Tuple[float, List[Tuple[str, float]], List[Tuple[str, float]]]:
        """Return (p_phishing, top phishing-indicative terms, top legit-indicative terms) with contributions = tfidf weight × coefficient."""
        vec = self.vectorize(doc)
        p = self._sigmoid(self.decision(vec))
        if self._inv is None:
            inv = [""] * self.n_features
            for t, j in self.vocab.items():
                inv[j] = t
            self._inv = inv
        contrib = sorted(((self._inv[j], v * self.coef[j]) for j, v in vec.items()), key=lambda x: -abs(x[1]))
        pos = [(t, w) for t, w in contrib if w > 0][:k_pos]
        neg = [(t, w) for t, w in contrib if w < 0][:k_neg]
        return p, pos, neg


def load(path: str = PORTABLE_PATH) -> Optional[PortableTfidfLR]:
    if not os.path.exists(path):
        return None
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        return PortableTfidfLR(json.load(f))
