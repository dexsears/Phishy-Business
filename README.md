# Phishy Business — Dashboard

**Because some links are looking kinda suspicious.**

**Project by:** Unpaid Interns

## Overview

Phishy Business is an interactive cybersecurity research dashboard that explores the characteristics of phishing and legitimate URLs.

The project investigates the research question:

**Are phishing URLs longer than legitimate URLs?**

It uses the PhiUSIIL Phishing URL dataset from the UCI Machine Learning Repository and presents statistical results and URL characteristics through an interactive web interface.

The dashboard is designed to make the research accessible while allowing administrators to inspect the underlying sample data and analysis outputs.

## Technology Stack

| Technology | Purpose |
|---|---|
| HTML5 | Dashboard structure |
| CSS3 | Layout and visual styling |
| JavaScript | Dashboard logic and interactions |
| Chart.js 4.4.1 | Data visualization |
| Python | Local statistical analysis |
| Cloudflare Pages | Static website hosting |
| Cloudflare Workers | Phishician AI backend |
| Groq API | AI response generation |

The dashboard is primarily a static website. It does not require a traditional backend to display its research findings.

Phishician operates separately through a Cloudflare Worker.

## Directory Contents

| File | Description |
|---|---|
| `index.html` | Main dashboard entry point |
| `styles.css` | Dashboard styling |
| `app.js` | Application logic, navigation, interactions, and role handling |
| `results.js` | Statistical results generated from the complete dataset |
| `sample.js` | Random sample used by interactive filters |
| `robots.txt` | Instructions for search engine crawlers |
| `README.md` | Website documentation |

## Dashboard Structure

The dashboard contains a sign-in screen followed by research and data exploration pages.

### User Role

The User role is intended for visitors who want to understand and explore the research.

Available pages:

**1. Overview**

Presents the main research statistics, headline results, and key information about the dataset.

**2. Explore**

Allows visitors to investigate URL characteristics and compare phishing and legitimate URLs through interactive filters and visualizations.

**3. Findings**

Presents the statistical results and interpretations of the research.

**4. About**

Provides information about the research question, dataset, methodology, and references.

### Admin Role

The Admin role includes all User features, with additional access to the Data page.

**Data**

Provides administrative research tools, including:

- Analysis pipeline information.
- Searchable sample data table.
- Inspection of individual URL records.
- CSV export of the available sample.

### Role Limitations

The current role system is implemented entirely on the frontend.

The Admin passcode is defined in `app.js` through:

```js
ADMIN_PASSCODE
```

Its default demonstration value is:

```text
interns
```

Change the passcode before presenting the project.

**Security notice:** These roles control interface visibility only. The passcode can be read from the JavaScript source, and the administrative data is not protected by actual authentication or authorization.

The role system is intended for demonstration purposes. Real access control would require server-side authentication and authorization.

## Phishician — AI Assistant

Phishician is the AI assistant integrated into Phishy Business.

It is designed to help users understand the dashboard, interpret research findings, and learn about phishing URL characteristics.

### Intended Capabilities

- Explain dashboard statistics in simple language.
- Interpret statistical findings.
- Explain URL characteristics and potential warning signs.
- Discuss the research methodology.
- Answer questions about phishing and online safety.

### AI Architecture

Phishician uses a separate Cloudflare Worker connected to the Groq API.

```text
Website (Cloudflare Pages)
          |
          | User question
          v
Phishician AI Worker
          |
          | API request
          v
Groq AI API
          |
          | Generated response
          v
Website
```

The AI Worker handles requests independently of the static dashboard.

The Groq API key is stored as a Cloudflare Worker secret and must never be exposed in frontend JavaScript or committed to GitHub.

The Worker uses an allowed-origins configuration to restrict browser-based cross-origin requests.

### AI Limitations

Phishician is an informational assistant, not a phishing detection engine.

It cannot independently visit or verify websites. When evaluating a URL, it can only reason from the URL text and the features supplied to it.

Its responses should not be treated as definitive security assessments.

## Data Integration

The dashboard consumes two generated JavaScript files.

| File | Data |
|---|---|
| `results.js` | Full-dataset statistical results and group summaries |
| `sample.js` | Approximately 8,000 sampled records for interactive exploration |

These files are generated by `analysis.py`, located in the `analysis/` directory.

The dashboard does not run the Python analysis itself.

For instructions on downloading the dataset and reproducing the analysis, see:

`../analysis/README.md`

### Demonstration Data

The initial `results.js` and `sample.js` files may contain simulated demonstration data.

The dashboard displays a yellow demo banner when demonstration data is loaded.

Before presenting or publishing the project, replace the demonstration files with the outputs of the actual analysis.

## Running Locally

### Requirements

- A modern web browser.
- An internet connection for Chart.js, which is loaded from cdnjs.
- Generated `results.js` and `sample.js` files.

### Instructions

1. Ensure the analysis has been completed.
2. Confirm that `results.js` and `sample.js` contain the actual generated data.
3. Open `index.html` in a web browser.

The dashboard can run as a static website without a local backend.

For local testing of Phishician, ensure its Worker is deployed and the frontend points to the correct Worker URL.

## Deployment — Cloudflare Pages

Phishy Business is designed to be hosted using Cloudflare Pages.

### Repository Structure

```text
phishy-business/
│
├── website/
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   ├── results.js
│   ├── sample.js
│   ├── robots.txt
│   └── README.md
│
├── ai-worker/
│   └── src/
│       └── index.js
│
├── analysis/
│   ├── analysis.py
│   ├── requirements.txt
│   └── README.md
│
└── .gitignore
```

### Cloudflare Pages Configuration

Connect the GitHub repository to Cloudflare Pages.

Use the following configuration:

| Setting | Value |
|---|---|
| Framework preset | None |
| Production branch | `main` |
| Root directory | `website` |
| Build command | Leave empty |
| Build output directory | `.` |

The website is deployed as static assets. No Python build process is required during deployment.

### AI Worker Configuration

Phishician is deployed separately through Cloudflare Workers.

The Worker requires the following environment configuration:

| Variable | Purpose |
|---|---|
| `GROQ_API_KEY` | Secret used to authenticate with Groq |
| `GROQ_MODEL` | AI model identifier |
| `ALLOWED_ORIGINS` | Permitted website origins |

Never commit API keys or other secrets to the repository.

## Dataset and Research Reference

**Dataset:** PhiUSIIL Phishing URL Dataset

**Source:** UCI Machine Learning Repository, Dataset 967

**Authors:** Prasad & Chandra (2024)

**DOI:** https://doi.org/10.1016/j.cose.2023.103545

**License:** CC BY 4.0

The project uses the dataset for academic research and educational exploration of phishing URL characteristics.

## Disclaimer

Phishy Business is an academic research and educational project.

Its findings describe patterns observed in the selected dataset and should not be generalized to all URLs or used as the sole basis for determining whether a website is safe.

A URL characteristic, including HTTPS, does not independently establish the legitimacy or safety of a website.

**Project by Unpaid Interns.**

Because some links are looking kinda suspicious.
