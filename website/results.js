window.RESULTS = {
 "demo": false,
 "source": "PhiUSIIL_Phishing_URL_Dataset.csv",
 "n": 235795,
 "n_phish": 100945,
 "n_legit": 134850,
 "length_cap": 144,
 "numeric": {
  "url_length": {
   "phish": {
    "mean": 46.24,
    "median": 34.0,
    "sd": 61.07
   },
   "legit": {
    "mean": 27.23,
    "median": 27.0,
    "sd": 4.82
   }
  },
  "dots": {
   "phish": {
    "mean": 2.38,
    "median": 2.0,
    "sd": 1.32
   },
   "legit": {
    "mean": 2.16,
    "median": 2.0,
    "sd": 0.4
   }
  },
  "hyphens": {
   "phish": {
    "mean": 0.71,
    "median": 0.0,
    "sd": 2.25
   },
   "legit": {
    "mean": 0.08,
    "median": 0.0,
    "sd": 0.31
   }
  }
 },
 "binary": {
  "https": {
   "phish_pct": 48.7,
   "legit_pct": 100.0
  },
  "at_symbol": {
   "phish_pct": 1.5,
   "legit_pct": 0.0
  }
 },
 "test": {
  "name": "Mann-Whitney U",
  "stat": 9824816173.0,
  "effect_name": "rank-biserial r",
  "reason": "URL length is heavily skewed (skewness 53.7), so a test based on ranks is safer than comparing averages.",
  "p": 0.0,
  "alpha": 0.05,
  "effect": 0.44,
  "skewness": 53.68,
  "effect_label": "moderate",
  "significant": true,
  "conclusion": "Phishing URLs are significantly longer than legitimate URLs (median 34 vs 27 characters)."
 }
};
