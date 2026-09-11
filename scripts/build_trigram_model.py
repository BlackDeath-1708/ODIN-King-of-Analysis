"""
Build English character trigram log-probability model.
Run once before training: python scripts/build_trigram_model.py
Output: backend/data/trigram_model.json
Format: {"the": -2.14, "ing": -2.31, ...}  (log2 probabilities)

Prefers the system dictionary (/usr/share/dict/words) since it's already
available offline in this environment; falls back to NLTK's word corpus if
the system dictionary isn't present.
"""
import json
import math
from collections import Counter
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "backend" / "data" / "trigram_model.json"
SYSTEM_WORDLIST = Path("/usr/share/dict/words")


def _load_corpus() -> str:
    if SYSTEM_WORDLIST.exists():
        return SYSTEM_WORDLIST.read_text(errors="ignore").lower()
    import nltk
    nltk.download('words', quiet=True)
    from nltk.corpus import words as nltk_words
    return ' '.join(nltk_words.words()).lower()


def build():
    corpus = _load_corpus()
    counts = Counter(corpus[i:i + 3] for i in range(len(corpus) - 2) if corpus[i:i + 3].isalpha())
    total = sum(counts.values())
    model = {tg: round(math.log2(c / total), 4) for tg, c in counts.items()}

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(model, f)
    print(f"Wrote {len(model)} trigrams to {OUTPUT}")


if __name__ == '__main__':
    build()
