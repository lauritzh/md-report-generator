#
# Lauritz Holtmann, (c) 2022 - 2023
#

import io
import os
import re
import yaml
import pdfkit
import datetime
import markdown
import xlsxwriter
import matplotlib.pyplot as plt
from cvss import CVSS3
from datetime import date
from string import Template

# Constants
content_dir = "content/"
findings_dir = "findings/"
boilerplate_dir = "boilerplate/"
page_break = '\n\n<div style = "display:block; clear:both; page-break-after:always;"></div>\n\n'

# Variables
config = {}
report_md = ""

# Set Base-URL to current working directory 
# Makes including images to report more easy by simply referencing images/test.png
report_md += "<base href=\"file://{}/\">\n\n".format(os.getcwd())


# Parse Config
with open('config.yaml') as f:
	config = yaml.load(f, Loader=yaml.FullLoader)
	print("Config options: {}".format(config))
	f.close()


# Glue: Collect files and build Markdown report
with open(content_dir + 'introduction.md') as f:
	report_md += f.read()
	report_md += page_break
	f.close()

with open(content_dir + 'scope.md') as f:
	report_md += f.read()
	report_md += page_break
	f.close()

with open(content_dir + 'technical-details.md') as f:
	report_md += f.read()
	report_md += page_break
	f.close()

# Insert Placeholders
report_md = report_md.format(
	title = config["title"], 
	author = config["author"], 
	customer = config["customer"],
	critical_findings = "{critical_findings}",
	high_findings = "{high_findings}",
	medium_findings = "{medium_findings}",
	low_findings = "{low_findings}",
	piechart = "{piechart}",
	findings_list = "{findings_list}"
)

######## Main Part of the Report: Detailed Description of Findings

# Iterate over finding MD files, preprocess
findings = []
for file in os.listdir(findings_dir):
	if file.endswith(".md"):
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
	else:
		print("File {} does not have correct file type .md".format(file))


# Sort findings, CVSS Score descending
def useScore(elem):
    return elem["cvss_score"]
findings.sort(key=useScore,reverse=True)

# Determine Statistics and Render Pie Chart
print("Generating Pie Chart...")

total_findings = len(findings)
critical_findings = len([finding for finding in findings if finding["cvss_severity"] == "Critical"])
high_findings = len([finding for finding in findings if finding["cvss_severity"] == "High"])
medium_findings = len([finding for finding in findings if finding["cvss_severity"] == "Medium"])
low_findings = len([finding for finding in findings if finding["cvss_severity"] == "Low"])
none_findings = len([finding for finding in findings if finding["cvss_severity"] == "None"])

## Data for the pie chart
labels = ['Critical', 'High', 'Medium', 'Low', 'None']
sizes = [critical_findings, high_findings, medium_findings, low_findings, none_findings]
colors = ['violet', 'red', 'orange', 'yellow', 'green']

## Set font size and padding for legend
plt.rcParams['font.size'] = 12
plt.rcParams['legend.fontsize'] = 12

## Create the pie chart as an SVG in memory
fig, ax = plt.subplots()
ax.pie(sizes, labels=None, colors=colors, autopct=lambda pct: f"{pct:.1f}%" if pct > 0 else '')
ax.axis('equal')
### Set legend
plt.subplots_adjust(left=0.1, right=0.5)
ax.legend(labels, loc='center left', bbox_to_anchor=(1, 0.5), title='Distribution of Findings by Severity')
svg_io = io.BytesIO()
plt.savefig(svg_io, format='svg')
svg_io.seek(0)
generated_piechart = svg_io.getvalue().decode('utf-8')

## Create the detailed table of findings
generated_table_of_findings = ""
for counter,finding in enumerate(findings):
	# Fill Template
	generated_table_of_findings += "* **{}**\t\#PEN{}{:04d}:\t{} ([CWE-{}](https://cwe.mitre.org/data/definitions/{}.html))\n".format(finding["cvss_severity"], date.today().year, counter+1, finding["title"], finding["CWE-ID"], finding["CWE-ID"])

# Insert Placeholders
report_md = report_md.format(
	critical_findings = critical_findings,
	high_findings = high_findings,
	medium_findings = medium_findings,
	low_findings = low_findings,
	piechart = "{piechart}",
	findings_list = generated_table_of_findings
)

# Append processed findings to report
for counter,finding in enumerate(findings):
	print("Appending finding {}...".format(finding["title"]))
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


# Append Conclusion and Appendix
with open(content_dir + 'conclusion.md') as f:
	report_md += f.read() 
	report_md += page_break
	f.close()

with open(content_dir + 'appendix.md') as f:
	report_md += f.read() 
	report_md += page_break
	f.close()


############

# Write findings to Excel file
print("Generating Excel file...")
excel_report = xlsxwriter.Workbook('report.xlsx')
excel_report_sheet = excel_report.add_worksheet("Findings")
bold = excel_report.add_format({'bold': True})
table_header = excel_report.add_format({'bold': True, 'bg_color': '#c8c8cf'})

# Title
excel_report_sheet.write(0, 0, "Pentest Report: {}".format(config["title"]), bold)
excel_report_sheet.write(1, 0, "Author: {}".format(config["author"]))
excel_report_sheet.write(2, 0, "Date: {}".format(datetime.datetime.now().strftime("%Y-%m-%d")))

# Table Header
excel_report_sheet.write(4, 0, "Finding-ID", table_header)
excel_report_sheet.write(4, 1, "Severity", table_header)
excel_report_sheet.write(4, 2, "Asset", table_header)
excel_report_sheet.write(4, 3, "Title", table_header)

# Findings
row = 5
col = 0 
for counter,finding in enumerate(findings):
    excel_report_sheet.write(row, col, "#PEN{}{:04d}".format(date.today().year,counter+1), bold)
    excel_report_sheet.write(row, col + 1, "{} ({})".format(finding["cvss_severity"], finding["cvss_score"]))
    excel_report_sheet.write(row, col + 2, finding["asset"])
    excel_report_sheet.write(row, col + 3, finding["title"])
    row += 1
 
excel_report.close()

############
print("Render Markdown to HTML...")
# Render Markdown: Convert to main report to HTML
report_html = markdown.markdown(report_md, extensions=['fenced_code', 'codehilite', 'tables'])

cover_location = "temp/cover_processed.html"
with open(boilerplate_dir + 'cover.html') as f:
	cover_processed = Template(f.read()).safe_substitute(title=config["title"], author=config["author"], date=datetime.datetime.now().strftime("%Y-%m-%d"), customer=config["customer"])
	f.close()

with open(cover_location, 'w') as f:
	f.write(cover_processed)
	f.close()

# Insert inlined SVG
report_html = report_html.replace("{piechart}", generated_piechart)

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
	"enable-local-file-access": None
}

css = boilerplate_dir + "report.css"

print("Generating PDF...")
pdfkit.from_string(report_html, 'report.pdf', options=options, css=css, toc=toc, cover=cover_location, cover_first=True)