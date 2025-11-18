# Markdown Pentest Report Generator
This repository contains a toolchain to generate pentest reports based on *Markdown* inputs.

## Setup
Clone repository:
```console
$ git clone https://github.com/lauritzh/md-report-generator.git
```

Install dependencies:
```console
$ make init
```

Run generation script for full report:
```console
$ make all
```

Alternatively only show findings:
```console
$ make view-findings
```

Or export single PDFs for each finding:
```console
$ make findings
```

## How-to
This repository can be cloned in order to obtain a self-containing pentest report with its generation script.

Basic configuration is available within the `config.yaml` file:
```yaml
title: "Example Report"
author: "Lauritz Holtmann"
customer: "Demo Company"
```

Content such as introduction and conclusion can be found within the `content/` directory:
```console
$ ls content    
conclusion.md		introduction.md		scope.md		technical-details.md
```

To add a new finding, copy an example file from `findings/` and adjust its contents. Each file contains basic meta data as HTML comment (YAML format) followed by the main contents of the finding:
```html
<!--
title: Example Vuln 
asset: Test Shop
CWE-ID: CWE-79
CWE-Link: https://cwe.mitre.org/data/definitions/79.html
cvss:
    AV: N # Attack Vector: Network (N), Adjacent (A), Local (L), Physical (P)
    AC: L # Attack Complexity: Low (L), High (H)
    AT: P # Attack Requirements: None (N), Present (P)
    PR: N # Privileges Required: None (N), Low (L), High (H)
    UI: A # User Interaction: None (N), Passive (P), Active (A)
    VC: H # Vulnerable System Confidentiality: High (H), Low (L), None (N)
    VI: L # Vulnerable System Integrity: High (H), Low (L), None (N)
    VA: N # Vulnerable System Availability: High (H), Low (L), None (N)
    SC: N # Subsequent System Confidentiality: High (H), Low (L), None (N)
    SI: N # Subsequent System Integrity: High (H), Low (L), None (N)
    SA: N # Subsequent System Availability: High (H), Low (L), None (N)
-->
Lorem Ipsum dolor sit amet...
[...]
```

Alternatively, you can provide a full CVSS 4.0 vector using the `vector` property inside the `cvss` block (e.g. `vector: CVSS:4.0/AV:N/...`). The generator will normalize it automatically.

## Upcoming Features
- [x] Add argument parser
- [x] Optional: Separate PDF files for findings (e.g. useful to share preliminary results with customer)
- [ ] Use constant finding IDs
- [ ] Add support for compiling from intermediate files (save Markdown and HTML files during generation)

## License
This repository is licensed under the [Unlicense](LICENSE).
