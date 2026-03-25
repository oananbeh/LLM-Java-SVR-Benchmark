"""
RAG Retrieval Module — CodeBERT-based cosine similarity retrieval.

Pipeline (matches paper Section 3.3):
  1. Load the CVEfixes corpus (500 Java vulnerability fix pairs).
  2. Encode all corpus snippets with CodeBERT.
  3. For each target vulnerability, encode its code snippet and
     retrieve the top-k most similar fix pairs.

The corpus embeddings are cached on disk so encoding only runs once.

Usage:
    retriever = RAGRetriever(corpus_path="data/cvefixes_corpus.csv")
    retriever.build_index()                      # encode + cache
    result = retriever.retrieve(code_snippet)    # top-1 by default
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

CACHE_PATH = Path(__file__).parent / "embeddings_cache.npy"
CORPUS_META_PATH = Path(__file__).parent / "corpus_meta.json"

CODEBERT_MODEL = "microsoft/codebert-base"


@dataclass
class RetrievedExample:
    rank: int
    similarity: float
    vulnerable_code: str
    fixed_code: str
    cwe_id: str
    source: str


class RAGRetriever:
    """
    Retrieves the most semantically similar vulnerability-fix pairs
    from a reference corpus using CodeBERT embeddings.
    """

    def __init__(self, corpus_path: str,
                 model_name: str = CODEBERT_MODEL,
                 device: Optional[str] = None,
                 cache_dir: Optional[str] = None):
        self.corpus_path = corpus_path
        self.model_name = model_name
        self.device = device
        self.cache_dir = Path(cache_dir) if cache_dir else Path(__file__).parent
        self._embeddings: Optional[np.ndarray] = None
        self._corpus_df: Optional[pd.DataFrame] = None
        self._model = None
        self._tokenizer = None

    # ------------------------------------------------------------------
    # Index construction
    # ------------------------------------------------------------------

    def build_index(self, force_rebuild: bool = False) -> None:
        """
        Encode corpus snippets and cache the embeddings array.
        Pass force_rebuild=True to re-encode even when cache exists.
        """
        cache_file = self.cache_dir / "embeddings_cache.npy"
        meta_file = self.cache_dir / "corpus_meta.json"

        self._corpus_df = pd.read_csv(self.corpus_path)
        self._validate_corpus()

        if not force_rebuild and cache_file.exists() and meta_file.exists():
            logger.info("Loading cached embeddings from %s", cache_file)
            self._embeddings = np.load(str(cache_file))
            logger.info("Loaded %d cached embeddings.", len(self._embeddings))
            return

        logger.info("Building CodeBERT index for %d corpus entries...",
                    len(self._corpus_df))
        self._load_model()

        snippets = self._corpus_df["vulnerable_code"].fillna("").tolist()
        self._embeddings = self._encode_batch(snippets)

        np.save(str(cache_file), self._embeddings)
        with open(meta_file, "w") as f:
            json.dump({"corpus_path": self.corpus_path,
                       "model": self.model_name,
                       "n_entries": len(self._corpus_df)}, f)
        logger.info("Index built and cached at %s", cache_file)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def retrieve(self, query_snippet: str, top_k: int = 1) -> list[RetrievedExample]:
        """
        Return the top-k most similar fix pairs for a given code snippet.
        build_index() must be called first.
        """
        if self._embeddings is None:
            raise RuntimeError("Call build_index() before retrieve().")

        self._load_model()
        query_emb = self._encode_single(query_snippet)

        # Cosine similarity
        norms = np.linalg.norm(self._embeddings, axis=1)
        query_norm = np.linalg.norm(query_emb)
        # Avoid division by zero
        norms = np.where(norms == 0, 1e-10, norms)
        similarities = (self._embeddings @ query_emb) / (norms * query_norm)

        top_indices = np.argsort(similarities)[::-1][:top_k]

        results = []
        for rank, idx in enumerate(top_indices, start=1):
            row = self._corpus_df.iloc[idx]
            results.append(RetrievedExample(
                rank=rank,
                similarity=float(similarities[idx]),
                vulnerable_code=row.get("vulnerable_code", ""),
                fixed_code=row.get("fixed_code", ""),
                cwe_id=str(row.get("cwe_id", "")),
                source=str(row.get("source", "")),
            ))
        return results

    # ------------------------------------------------------------------
    # Model helpers
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        if self._model is not None:
            return
        try:
            import torch
            from transformers import AutoTokenizer, AutoModel

            self.device = self.device or ("cuda" if torch.cuda.is_available() else "cpu")
            logger.info("Loading CodeBERT model '%s' on %s...", self.model_name, self.device)
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModel.from_pretrained(self.model_name).to(self.device)
            self._model.eval()
        except ImportError:
            raise ImportError(
                "transformers and torch are required for RAG. "
                "Install with: pip install transformers torch"
            )

    def _encode_single(self, code: str) -> np.ndarray:
        return self._encode_batch([code])[0]

    def _encode_batch(self, snippets: list[str],
                      batch_size: int = 32) -> np.ndarray:
        import torch
        all_embeddings = []
        for i in range(0, len(snippets), batch_size):
            batch = snippets[i: i + batch_size]
            inputs = self._tokenizer(
                batch,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=512,
            ).to(self.device)
            with torch.no_grad():
                outputs = self._model(**inputs)
                # [CLS] token embedding as the snippet representation
                embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
            all_embeddings.append(embeddings)
            if (i // batch_size) % 10 == 0:
                logger.debug("Encoded batch %d/%d", i // batch_size + 1,
                             len(snippets) // batch_size + 1)
        return np.vstack(all_embeddings)

    def _validate_corpus(self) -> None:
        required = {"vulnerable_code", "fixed_code"}
        missing = required - set(self._corpus_df.columns)
        if missing:
            raise ValueError(
                f"Corpus CSV is missing required columns: {missing}. "
                f"Expected columns: vulnerable_code, fixed_code, cwe_id, source"
            )


# ------------------------------------------------------------------
# Corpus download helper (CVEfixes subset)
# ------------------------------------------------------------------

def prepare_cvefixes_corpus(output_path: str = "data/cvefixes_corpus.csv",
                             n_samples: int = 500) -> None:
    """
    Prepares the 500-entry CVEfixes Java corpus used in the RAG experiments.
    This selects Java fix pairs from the CVEfixes dataset.

    CVEfixes dataset: https://github.com/secureIT-project/CVEfixes
    You must download the CVEfixes SQLite database manually and pass its
    path via the CVEFIXES_DB env variable.

    The resulting CSV has columns: vulnerable_code, fixed_code, cwe_id, source.
    """
    import sqlite3

    db_path = os.environ.get("CVEFIXES_DB")
    if not db_path or not os.path.exists(db_path):
        raise EnvironmentError(
            "Set CVEFIXES_DB env variable to the path of the CVEfixes SQLite DB. "
            "Download from: https://zenodo.org/record/7029359"
        )

    conn = sqlite3.connect(db_path)
    query = """
        SELECT
            f.before_change  AS vulnerable_code,
            f.after_change   AS fixed_code,
            c.cwe_id         AS cwe_id,
            cv.cve_id        AS source
        FROM file_change f
        JOIN commits cm ON f.hash = cm.hash
        JOIN fixes fx   ON cm.hash = fx.hash
        JOIN cve cv     ON fx.cve_id = cv.cve_id
        LEFT JOIN cwe c ON cv.cve_id = c.cve_id
        WHERE f.programming_language = 'Java'
          AND f.before_change IS NOT NULL
          AND f.after_change IS NOT NULL
          AND length(f.before_change) > 30
        ORDER BY RANDOM()
        LIMIT ?
    """
    df = pd.read_sql_query(query, conn, params=(n_samples,))
    conn.close()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info("Saved %d CVEfixes corpus entries to %s", len(df), output_path)
