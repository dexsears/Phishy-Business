"""Phishy Business - analysis script (Unpaid Interns).

Reads the PhiUSIIL Phishing URL dataset, builds features from the URL text,
tests whether phishing URLs are longer, and writes two files for the dashboard.
  results.js  statistics from ALL rows (group summaries and the headline test)
  sample.js   seeded random sample, stratified by label, used by the filters

Usage
  python analysis.py --csv PhiUSIIL_Phishing_URL_Dataset.csv
  python analysis.py --demo     # simulated data, for layout testing only
"""
import argparse, json, pathlib, sys
import numpy as np
import pandas as pd
from scipy import stats

LABEL_PHISHING = 0                 # PhiUSIIL uses label 1 = legitimate, 0 = phishing
ALPHA, SEED, SAMPLE_SIZE = 0.05, 42, 8000
REQUIRED = ["URL", "label", "TLD"]  # columns the script cannot work without
FEATURES = ["label", "url_length", "dots", "hyphens", "https", "at_symbol", "tld"]
OUT = pathlib.Path(__file__).resolve().parent


def load_csv(path):
    """Read the CSV and derive every feature from the URL text."""
    raw = pd.read_csv(path, usecols=lambda c: c in REQUIRED + ["URLLength", "IsHTTPS"])
    missing = [c for c in REQUIRED if c not in raw.columns]
    if missing:
        sys.exit(f"Column(s) {missing} not found in {path}. Columns present: {list(raw.columns)}")
    raw = raw.dropna(subset=["URL", "label"])
    url = raw["URL"].astype(str)
    df = pd.DataFrame({
        "label": raw["label"].astype(int),
        "url_length": url.str.len(),
        "dots": url.str.count(r"\."),
        "hyphens": url.str.count("-"),
        "https": url.str.lower().str.startswith("https://").astype(int),
        "at_symbol": url.str.contains("@", regex=False).astype(int),
        "tld": raw["TLD"].astype(str).str.lower().str.strip(),
    })
    # Sanity checks against the dataset's own columns (printed, not enforced).
    if "URLLength" in raw:
        print(f"Derived length matches URLLength in {(raw['URLLength'] == df['url_length']).mean():.2%} of rows")
    if "IsHTTPS" in raw:
        print(f"Derived https matches IsHTTPS in {(raw['IsHTTPS'] == df['https']).mean():.2%} of rows")
    return df


def make_demo(n=20000):
    """Simulated data so the layout can be tested. NOT real findings."""
    rng = np.random.default_rng(SEED)
    ph = rng.random(n) < 0.45
    tlds = ["com", "org", "net", "info", "xyz", "top", "co", "io", "uk", "de"]
    pw = np.array([30, 5, 8, 8, 14, 12, 8, 6, 5, 4.0])
    lw = np.array([60, 12, 8, 3, 1, 1, 6, 4, 3, 2.0])
    return pd.DataFrame({
        "label": np.where(ph, LABEL_PHISHING, 1 - LABEL_PHISHING),
        "url_length": np.where(ph, rng.lognormal(3.9, 0.55, n), rng.lognormal(3.4, 0.3, n)).round().astype(int),
        "dots": np.where(ph, rng.poisson(2.4, n), rng.poisson(2.1, n)),
        "hyphens": np.where(ph, rng.poisson(0.7, n), rng.poisson(0.1, n)),
        "https": np.where(ph, rng.random(n) < 0.5, 1).astype(int),
        "at_symbol": np.where(ph, rng.random(n) < 0.02, 0).astype(int),
        "tld": np.where(ph, rng.choice(tlds, n, p=pw / pw.sum()), rng.choice(tlds, n, p=lw / lw.sum())),
    })


def describe(s):
    return {"mean": round(float(s.mean()), 2), "median": round(float(s.median()), 2), "sd": round(float(s.std()), 2)}


def effect_label(effect, is_rank):
    """Plain-word size of the effect (common cut-offs for r and for Cohen's d)."""
    cuts = (0.1, 0.3, 0.5) if is_rank else (0.2, 0.5, 0.8)
    a = abs(effect)
    return "negligible" if a < cuts[0] else "small" if a < cuts[1] else "moderate" if a < cuts[2] else "large"


def run_test(phish, legit, all_len):
    """H0 - phishing and legitimate URLs have the same length. Test chosen by skewness."""
    skew = abs(float(stats.skew(all_len)))
    if skew > 1:
        u, p = stats.mannwhitneyu(phish, legit, alternative="two-sided")
        effect = 2 * u / (len(phish) * len(legit)) - 1  # rank-biserial correlation
        test = {"name": "Mann-Whitney U", "stat": round(float(u), 1), "effect_name": "rank-biserial r",
                "reason": f"URL length is heavily skewed (skewness {skew:.1f}), so a test based on ranks is safer than comparing averages."}
    else:
        t, p = stats.ttest_ind(phish, legit, equal_var=False)
        effect = (phish.mean() - legit.mean()) / np.sqrt((phish.var() + legit.var()) / 2)  # Cohen's d
        test = {"name": "Welch t-test", "stat": round(float(t), 2), "effect_name": "Cohen's d",
                "reason": f"URL length is not heavily skewed (skewness {skew:.1f}), so a t-test on the averages is fine."}
    sig = bool(p < ALPHA)
    direction = "longer" if phish.median() > legit.median() else "shorter"
    test.update({"p": float(p), "alpha": ALPHA, "effect": round(float(effect), 2), "skewness": round(skew, 2),
                 "effect_label": effect_label(effect, test["name"] == "Mann-Whitney U"), "significant": sig,
                 "conclusion": (f"Phishing URLs are significantly {direction} than legitimate URLs "
                                f"(median {phish.median():.0f} vs {legit.median():.0f} characters)." if sig else
                                "No significant difference in URL length between phishing and legitimate sites.")})
    return test


def write_js(name, variable, data, **kw):
    (OUT / name).write_text(f"window.{variable} = " + json.dumps(data, **kw) + ";\n")
    print(f"Wrote {name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="path to PhiUSIIL_Phishing_URL_Dataset.csv")
    ap.add_argument("--demo", action="store_true", help="use simulated data")
    args = ap.parse_args()
    if not args.csv and not args.demo:
        ap.error("give --csv <file> or --demo")

    df = make_demo() if args.demo else load_csv(args.csv)
    is_ph = df["label"] == LABEL_PHISHING
    phish, legit = df[is_ph], df[~is_ph]
    print(f"Rows: {len(df)} (phishing {len(phish)}, legitimate {len(legit)})")

    # ---- full-dataset statistics -> results.js
    results = {"demo": bool(args.demo), "source": "simulated data" if args.demo else pathlib.Path(args.csv).name,
               "n": len(df), "n_phish": len(phish), "n_legit": len(legit),
               "length_cap": int(np.ceil(np.percentile(df["url_length"], 99))),
               "numeric": {f: {"phish": describe(phish[f]), "legit": describe(legit[f])}
                           for f in ["url_length", "dots", "hyphens"]},
               "binary": {f: {"phish_pct": round(float(phish[f].mean() * 100), 1),
                              "legit_pct": round(float(legit[f].mean() * 100), 1)} for f in ["https", "at_symbol"]},
               "test": run_test(phish["url_length"], legit["url_length"], df["url_length"])}
    t = results["test"]
    print(f"{t['name']}: p = {t['p']:.3g}, {t['effect_name']} = {t['effect']} ({t['effect_label']})")
    write_js("results.js", "RESULTS", results, indent=1)

    # ---- seeded sample, same label mix as the full data -> sample.js
    sample = df.groupby("label", group_keys=False).sample(frac=min(1, SAMPLE_SIZE / len(df)), random_state=SEED)
    meta = {"demo": bool(args.demo), "seed": SEED, "size": len(sample), "phishing_label": LABEL_PHISHING}
    write_js("sample.js", "SAMPLE", {"meta": meta, **{c: sample[c].tolist() for c in FEATURES}}, separators=(",", ":"))


if __name__ == "__main__":
    main()
