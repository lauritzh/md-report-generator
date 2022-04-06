#
# Lauritz Holtmann, 2022
#

import os
import yaml
import pdfkit
import datetime
import markdown
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

for file in os.listdir(findings_dir):
	filename = os.fsdecode(file)
	with open(findings_dir + filename) as f:
		report_md += f.read()
		report_md += page_break
		f.close()

with open(boilerplate_dir + 'conclusion.md') as f:
	report_md += f.read() 
	report_md += page_break
	f.close()

# Render Markdown: Convert to main report to HTML
report_html = markdown.markdown(report_md, extensions=['codehilite', 'tables'])

# Insert Placeolders
report_md = report_md.format(title = config["title"], author = config["author"])

cover_location = "temp/cover_processed.html"
with open(boilerplate_dir + 'cover.html') as f:
	cover_processed = Template(f.read()).safe_substitute(title=config["title"], author=config["author"], date=datetime.datetime.now().strftime("%Y-%m-%d"))
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
	'margin-bottom': '0.75cm', 
    '--footer-html': boilerplate_dir + 'footer.html',
	'footer-right': '[page] of [topage]',
	'encoding': "UTF-8",
	'page-size': 'A4',
	'margin-top': '1.5cm',
}

css = boilerplate_dir + "report.css"

pdfkit.from_string(report_html, 'report.pdf', options=options, css=css, toc=toc, cover=cover_location, cover_first=True)
#pdfkit.from_string(report_html, 'report.pdf')