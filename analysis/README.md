# Phishy Business — Data Analysis

**Project:** Phishy Business  
**Group:** Unpaid Interns  
**Research Question:** Are phishing URLs longer than legitimate URLs?

## Overview

This directory contains the Python-based data analysis pipeline for Phishy Business.

The script reads the PhiUSIIL Phishing URL dataset, processes URL characteristics, performs statistical comparisons, and generates JavaScript files consumed by the dashboard.

The analysis is performed locally. The website does not need to execute Python or access the original dataset when visitors use it.

## Dataset

**PhiUSIIL Phishing URL Dataset**

- Source: [UCI Machine Learning Repository — Dataset 967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
- Authors: Prasad & Chandra (2024)
- License: CC BY 4.0
- DOI: [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545)

The dataset contains phishing and legitimate URLs alongside extracted URL characteristics.

### Label Encoding

| Label | Meaning |
|---|---|
| 1 | Legitimate |
| 0 | Phishing |

### Required Columns

The analysis script requires the following columns:

| Column | Purpose |
|---|---|
| `URL` | Original URL text used to calculate URL characteristics |
| `label` | Identifies whether the URL is legitimate or phishing |
| `TLD` | Top-level domain information |

The script also checks its calculated URL length and HTTPS counts against the dataset's `URLLength` and `IsHTTPS` columns when available.

## Directory Contents

| File | Description |
|---|---|
| `analysis.py` | Main analysis script |
| `requirements.txt` | Python package dependencies |
| `README.md` | Analysis documentation |

The script generates the following files in the website directory:

| Generated File | Description |
|---|---|
| `website/results.js` | Statistical results calculated using the full dataset, including the headline test and group summaries |
| `website/sample.js` | Seeded random sample used by the dashboard's interactive filters |

The generated files replace the initial simulated demonstration data.

## Requirements

- Python 3.9 or newer
- The PhiUSIIL dataset in CSV format
- Packages listed in `requirements.txt`

## Reproducing the Analysis

### 1. Install dependencies

From the `analysis/` directory, run:

```bash
pip install -r requirements.txt
```

### 2. Download the dataset

Download the PhiUSIIL dataset from:

https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

Place the downloaded CSV in the `analysis/` directory.

Expected filename:

```text
PhiUSIIL_Phishing_URL_Dataset.csv
```

### 3. Run the analysis

From the `analysis/` directory, execute:

```bash
python analysis.py --csv PhiUSIIL_Phishing_URL_Dataset.csv
```

The script will:

1. Read the dataset.
2. Validate the required columns.
3. Extract URL characteristics from the URL text.
4. Calculate descriptive statistics.
5. Select and perform the appropriate statistical test.
6. Calculate the effect size.
7. Generate `results.js` and `sample.js` in the website directory.
8. Print validation information comparing calculated URL length and HTTPS counts with the corresponding dataset columns.

If a required column is missing, the script stops and reports the issue.

### 4. Verify the generated files

After a successful run, check that these files exist:

```text
website/
├── results.js
└── sample.js
```

Make sure the dashboard is using the newly generated files rather than the original demonstration data.

## Statistical Methodology

### URL Characteristics

The script extracts the following characteristics from the URL text:

- URL length
- Number of dots
- Number of hyphens
- Presence of HTTPS
- Presence of the `@` symbol
- Top-level domain information

These characteristics are used to compare phishing and legitimate URLs.

### Statistical Testing

URL length distributions can be skewed. Because of this, the script uses a conditional statistical testing approach:

| Condition | Statistical Test |
|---|---|
| Skewness above 1 | Mann–Whitney U test |
| Otherwise | Welch's t-test |

The selected test is used to compare URL lengths between phishing and legitimate groups.

### Effect Size

The analysis calculates the rank-biserial correlation coefficient (rank-biserial r) as the effect size.

This provides information about the magnitude and direction of the difference between the two groups, beyond statistical significance alone.

### Interpretation

The statistical results should be interpreted in the context of the dataset.

A statistically significant difference does not automatically mean URL length can reliably identify phishing URLs. URL length is only one characteristic among many, and the analysis does not establish causation.

## Reproducibility

The random sample uses a fixed seed:

```text
42
```

This ensures that repeated runs with the same dataset and analysis settings produce the same sampled records.

The full-dataset statistics and the dashboard sample serve different purposes:

- `results.js` contains statistics calculated from the complete dataset.
- `sample.js` contains approximately 8,000 randomly selected records, preserving the dataset's phishing and legitimate class proportions, for interactive exploration.

## Demonstration Mode

To test the dashboard layout without the original dataset, run:

```bash
python analysis.py --demo
```

This generates simulated demonstration data.

**Important:** Demonstration data must not be presented as actual research findings. The dashboard displays a yellow demo banner when demonstration data is loaded.

Always run the real analysis before presenting or publishing the research results.

## Project Structure

```text
phishy-business/
│
├── analysis/
│   ├── analysis.py
│   ├── requirements.txt
│   └── README.md
│
└── website/
    ├── index.html
    ├── styles.css
    ├── app.js
    ├── results.js
    ├── sample.js
    └── README.md
```

## Research Reference

Prasad, A., & Chandra, S. (2024). PhiUSIIL Phishing URL Dataset.

Dataset source: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

DOI: https://doi.org/10.1016/j.cose.2023.103545

Dataset license: CC BY 4.0.
