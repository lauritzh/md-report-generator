#
# Lauritz Holtmann, (c) 2022
#

import os
import re
import yaml
import pdfkit
import datetime
import markdown
from cvss import CVSS3
from datetime import date
from string import Template

# Constants
boilerplate_dir = "boilerplate/"
findings_dir = "findings/"
page_break = '\n\n<div style = "display:block; clear:both; page-break-after:always;"></div>'

# Variables
config = {}
report_md = ""

# Parse Config
with open('config.yaml') as f:
	config = yaml.load(f, Loader=yaml.FullLoader)
	print("Config options: {}".format(config))
	f.close()


# Glue: Collect files and build Markdown report
with open(boilerplate_dir + 'introduction.md') as f:
	report_md += f.read()
	report_md += page_break
	f.close()

with open(boilerplate_dir + 'scope.md') as f:
	report_md += f.read()
	report_md += page_break
	f.close()

with open(boilerplate_dir + 'technical-details.md') as f:
	report_md += f.read()
	report_md += page_break
	f.close()

# Insert Placeholders
report_md = report_md.format(title = config["title"], author = config["author"], customer = config["customer"])

######## Main Part of the Report: Detailed Description of Findings

# Iterate over finding MD files, preprocess
findings = []
for file in os.listdir(findings_dir):
	filename = os.fsdecode(file)
	with open(findings_dir + filename) as f:
		print("Processing finding {}...".format(filename))
		finding = {}

		# Map finding description from MD file
		finding["description"] = f.read()
		f.close()

		# Parse Properties from Header Section
		re_search = re.search(r"<!--[\r\n]([\s\S]*)[\r\n]-->", finding["description"])
		properties_yaml = re_search.group(1)
		properties = yaml.load(properties_yaml, Loader=yaml.FullLoader)
		# Cleanup: Remove properties
		finding["description"] = finding["description"].replace(re_search.group(0), "")

		# Map Properties
		finding["title"] = properties["title"]
		finding["asset"] = properties["asset"]
		finding["CWE-ID"] = properties["CWE-ID"]
		finding["CWE-Link"] = properties["CWE-Link"]

		# calculate CVSS score and severity
		cvss_vector = "CVSS:3.0/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}".format(properties["cvss"]["AV"], properties["cvss"]["AC"], properties["cvss"]["PR"], properties["cvss"]["UI"], properties["cvss"]["S"], properties["cvss"]["C"], properties["cvss"]["I"],properties["cvss"]["A"])
		c = CVSS3(cvss_vector)
		finding["cvss_vector"] = c.clean_vector()
		finding["cvss_score"] = c.scores()[0]
		finding["cvss_severity"] = c.severities()[0]

		findings.append(finding)

# Sort findings, CVSS Score descending
def useScore(elem):
    return elem["cvss_score"]
findings.sort(key=useScore,reverse=True)

# Append processed findings to report
for counter,finding in enumerate(findings):
	# Fill Template
	report_md += """
### \#PEN{}{:04d}: {}

---

| Asset         | CWE                                                      | Severity (CVSS v3.0 Base Score) | CVSS v3.0 Vektor                                                                             |
|---------------|----------------------------------------------------------|---------------------------------|----------------------------------------------------------------------------------------------|
| {} | [{}]({}) | {} ({})                      | *{}* |

---

{}
	""".format(
		date.today().year,
		counter+1,
		finding["title"],
		finding["asset"],
		finding["CWE-ID"],
		finding["CWE-Link"],
		finding["cvss_severity"],
		finding["cvss_score"],
		finding["cvss_vector"],
		finding["description"]
	)
	report_md += page_break


# Append Conclusion
with open(boilerplate_dir + 'conclusion.md') as f:
	report_md += f.read() 
	report_md += page_break
	f.close()

############

# Render Markdown: Convert to main report to HTML
report_html = markdown.markdown(report_md, extensions=['fenced_code', 'codehilite', 'tables'])

cover_location = "temp/cover_processed.html"
with open(boilerplate_dir + 'cover.html') as f:
	cover_processed = Template(f.read()).safe_substitute(title=config["title"], author=config["author"], date=datetime.datetime.now().strftime("%Y-%m-%d"), customer=config["customer"])
	f.close()

with open(cover_location, 'w') as f:
	f.write(cover_processed)
	f.close()

# Generate PDF
toc = {
	'xsl-style-sheet': boilerplate_dir + 'toc.xsl'
}

options = {
	'--header-html': boilerplate_dir + 'header.html',
    '--footer-html': boilerplate_dir + 'footer.html',
	#'footer-right': '[page] of [topage]',
	'footer-right': '[page]',
	'footer-font-name': 'avenir next',
	'margin-bottom': '0.75cm', 
	'margin-top': '1.5cm',
	'header-spacing': '-5',
	'encoding': "UTF-8",
	'page-size': 'A4',
}

css = boilerplate_dir + "report.css"

pdfkit.from_string(report_html, 'report.pdf', options=options, css=css, toc=toc, cover=cover_location, cover_first=True)