"""
Train the DGA / DNS-tunnelling RandomForest classifier.

Dataset construction (2026-09-11 rework -- see ML_MODELS.md): PS 26145
names "DGA samples from published algorithms (e.g., via DGArchive)" as its
suggested methodology. This repo has no DGArchive access (registration-
gated), but the *algorithmic shape* of well-documented DGA families is
public security-research knowledge (see Antonakakis et al. 2012, Plohmann
et al.'s DGArchive paper 2016) and safely reimplementable without any
actual malware binary or DGArchive dataset -- each generator below
reproduces one real family's publicly-documented distinguishing structure
(length range, charset, TLD set, seeding style), not a byte-for-byte replay
of real malware output (which would require the actual binaries/seeds).
This is a meaningfully closer match to the PS's suggested methodology than
the previous single generic "random string" generator, and is the standard
way DGA classifiers are built/evaluated in published research when the
DGArchive dataset itself isn't available.

  BENIGN (label=0): single dictionary words as the hostname label (mimics
    real short brand-style domains: "github.com", "reddit.net"), common TLDs.
  RANDOM-CHARSET families (label=1): CONFICKER (short, length 4-9, small
    TLD set), CRYPTOLOCKER (longer, length 12-20), ZEUS_GAMEOVER (MD5-hash-
    derived 16-char label, mimicking its hash-based generation), NECURS
    (longest, length 16-25, occasional digits), TINBA (short, length 8-12,
    narrow TLD set), RAMNIT (consonant-weighted alternation, distinct
    character distribution from uniform-random).
  STRUCTURED families (label=1): BANJORI (a small set of fixed base words
    each mutated at one character position plus a numeric suffix -- very
    low overall entropy in a narrow position, the opposite pattern from the
    random-charset families, exercises a different part of the feature
    space), SUPPOBOX (exactly 2 real English words concatenated, e.g.
    "sunshinevalley.com"), MATSNU (2-3 real English words, sometimes with
    a trailing digit).

Feature extraction reuses extract_features() from backend/detectors/dga.py
directly, so train-time and serve-time feature computation are identical
by construction -- no risk of the two drifting apart.

Run: backend/.venv/bin/python3 training/train_dga.py
Saves: backend/ml_models/dga_model.joblib, backend/ml_models/dga_cal_data.npz
Updates: ML_MODELS.md is NOT auto-updated -- update it by hand with the
printed classification report after this runs.
"""

import random
import string
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.metrics import classification_report

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from detectors.dga import extract_features  # noqa: E402

WORDLIST_PATH = REPO_ROOT / "backend" / "data" / "english_wordlist.txt"
TRIGRAM_PATH  = REPO_ROOT / "backend" / "data" / "trigram_model.json"
MODEL_OUT     = REPO_ROOT / "backend" / "ml_models" / "dga_model.joblib"
CAL_DATA_OUT  = REPO_ROOT / "backend" / "ml_models" / "dga_cal_data.npz"

COMMON_TLDS   = ['com', 'net', 'org', 'io', 'co']
UNCOMMON_TLDS = ['ru', 'cn', 'biz', 'info', 'top', 'xyz']

random.seed(42)
np.random.seed(42)


def load_resources():
    import json
    with open(TRIGRAM_PATH) as f:
        trigram_model = json.load(f)
    with open(WORDLIST_PATH) as f:
        words = [w.strip().lower() for w in f if 3 <= len(w.strip()) <= 10 and w.strip().isalpha()]
    return trigram_model, words


def gen_benign(words: list, n: int) -> list:
    out = []
    for _ in range(n):
        word = random.choice(words)
        tld = random.choice(COMMON_TLDS)
        out.append((f"{word}.{tld}", 0))
    return out


def gen_conficker(n: int) -> list:
    tlds = ['com', 'net', 'org', 'info', 'biz', 'ws']
    out = []
    for _ in range(n):
        length = random.randint(4, 9)
        label = ''.join(random.choices(string.ascii_lowercase, k=length))
        out.append((f"{label}.{random.choice(tlds)}", 1))
    return out


def gen_cryptolocker(n: int) -> list:
    tlds = ['com', 'net', 'org', 'info', 'biz', 'ru']
    out = []
    for _ in range(n):
        length = random.randint(12, 20)
        label = ''.join(random.choices(string.ascii_lowercase, k=length))
        out.append((f"{label}.{random.choice(tlds)}", 1))
    return out


def gen_zeus_gameover(n: int) -> list:
    import hashlib
    tlds = ['com', 'net', 'biz', 'ru', 'info', 'org']
    out = []
    for _ in range(n):
        seed = str(random.randint(0, 10 ** 12)).encode()
        label = hashlib.md5(seed).hexdigest()[:16]
        out.append((f"{label}.{random.choice(tlds)}", 1))
    return out


def gen_necurs(n: int) -> list:
    tlds = ['com', 'net', 'org', 'info', 'biz', 'top', 'xyz']
    charset = list(string.ascii_lowercase) * 3 + list(string.digits)
    out = []
    for _ in range(n):
        length = random.randint(16, 25)
        label = ''.join(random.choices(charset, k=length))
        out.append((f"{label}.{random.choice(tlds)}", 1))
    return out


def gen_tinba(n: int) -> list:
    tlds = ['com', 'net', 'biz', 'info']
    out = []
    for _ in range(n):
        length = random.randint(8, 12)
        label = ''.join(random.choices(string.ascii_lowercase, k=length))
        out.append((f"{label}.{random.choice(tlds)}", 1))
    return out


def gen_ramnit(n: int) -> list:
    tlds = ['com', 'net', 'org']
    consonants = 'bcdfghjklmnpqrstvwxyz'
    both = consonants + 'aeiou'
    out = []
    for _ in range(n):
        length = random.randint(8, 16)
        label = ''.join(
            random.choice(consonants) if i % 2 == 0 else random.choice(both)
            for i in range(length)
        )
        out.append((f"{label}.{random.choice(tlds)}", 1))
    return out


def gen_banjori(n: int) -> list:
    base_words = ['flowershop', 'footballfan', 'sunrisevalley', 'bluewaterlake', 'goldstarmedia']
    tlds = ['com', 'net']
    out = []
    for _ in range(n):
        base = random.choice(base_words)
        pos = random.randint(0, len(base) - 1)
        mutated = base[:pos] + random.choice(string.ascii_lowercase) + base[pos + 1:]
        suffix = str(random.randint(1, 9999))
        out.append((f"{mutated}{suffix}.{random.choice(tlds)}", 1))
    return out


def gen_suppobox(words: list, n: int) -> list:
    """Suppobox: exactly 2 real dictionary words concatenated, .com/.net only."""
    out = []
    for _ in range(n):
        label = ''.join(random.sample(words, 2))
        out.append((f"{label}.{random.choice(['com', 'net'])}", 1))
    return out


def gen_matsnu(words: list, n: int) -> list:
    """Matsnu: 2-3 real dictionary words, sometimes a trailing digit."""
    out = []
    for _ in range(n):
        n_words = random.randint(2, 3)
        label = ''.join(random.sample(words, n_words))
        if random.random() < 0.3:
            label += str(random.randint(0, 99))
        out.append((f"{label}.{random.choice(COMMON_TLDS)}", 1))
    return out


def main():
    trigram_model, words = load_resources()

    samples = (
        gen_benign(words, 6000)
        + gen_conficker(1500)
        + gen_cryptolocker(1500)
        + gen_zeus_gameover(1500)
        + gen_necurs(1500)
        + gen_tinba(1000)
        + gen_ramnit(1000)
        + gen_banjori(1000)
        + gen_suppobox(words, 2000)
        + gen_matsnu(words, 2000)
    )
    random.shuffle(samples)
    print(f"Total samples: {len(samples)} "
          f"(benign: {sum(1 for _, l in samples if l == 0)}, "
          f"dga: {sum(1 for _, l in samples if l == 1)})")

    X, y, groups = [], [], []
    for query, label in samples:
        X.append(extract_features(query, trigram_model, set(words)))
        y.append(label)
        groups.append(round(len(query) / 5) * 5)  # group by length bucket -- prevents length leakage across folds

    X = np.array(X)
    y = np.array(y)
    groups = np.array(groups)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    gkf = GroupKFold(n_splits=5)
    fold_f1s = []
    for fold, (tr_idx, te_idx) in enumerate(gkf.split(X, y, groups)):
        clf = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
        clf.fit(X[tr_idx], y[tr_idx])
        preds = clf.predict(X[te_idx])
        report = classification_report(y[te_idx], preds, output_dict=True, zero_division=0)
        fold_f1s.append(report['1']['f1-score'])
        print(f"Fold {fold}: F1(dga)={report['1']['f1-score']:.4f}")

    print(f"\nMean GroupKFold F1(dga): {np.mean(fold_f1s):.4f}")

    # Final model on the full train split, held-out test evaluation
    final_model = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
    final_model.fit(X_train, y_train)
    test_preds = final_model.predict(X_test)
    print("\nHeld-out test set classification report:")
    print(classification_report(y_test, test_preds, target_names=['benign', 'dga'], zero_division=0))

    # Calibration hold-out: split X_train again into train/cal for Phase 3
    X_fit, X_cal, y_fit, y_cal = train_test_split(X_train, y_train, test_size=0.25, stratify=y_train, random_state=42)
    calibration_model = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
    calibration_model.fit(X_fit, y_fit)
    np.savez(CAL_DATA_OUT, X=X_cal, y=y_cal, X_test=X_test, y_test=y_test)
    print(f"\nSaved calibration hold-out data to {CAL_DATA_OUT}")

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, MODEL_OUT)
    print(f"Saved model to {MODEL_OUT}")


if __name__ == '__main__':
    main()
