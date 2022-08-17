# Markdown Pentest Report Generator
This repository contains a toolchain to generate pentest reports based on *Markdown* inputs.

## Setup
Clone repository:
```console
$ git clone https://github.com/lauritzh/md-report-generator.git
```

Install dependencies:
```console
$ pip3 install -r requirements.txt
```

Run generation script:
```console
$  python3 generate.py 
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
    PR: N # Privileges Required: None (N), Low (L), High (H)
    UI: R # User Interaction: None (N), Required (R)
    S: U # Unchanged (U), Changed (C)
    C: H # Confidentiality: High (H), Low (L), None (N)
    I: L # Integrity: High (H), Low (L), None (N)
    A: N # Availability: High (H), Low (L), None (N)
-->
Lorem Ipsum dolor sit amet...
[...]
```