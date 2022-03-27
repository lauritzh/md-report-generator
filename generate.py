#
# Lauritz Holtmann, 2022
#

import os
import yaml
import pdfkit
import markdown

# Constants
boilerplate_dir = "boilerplate/"
findings_dir = "findings/"
page_break = '<div style = "display:block; clear:both; page-break-after:always;"></div>'

# Variables
config = {}
report_md = ""


# Parse Config
with open('config.yaml') as f:
	config = yaml.load(f, Loader=yaml.FullLoader)
	print(config)


# Glue: Collect files and build Markdown report
with open(boilerplate_dir + 'cover.md') as f:
	report_md += f.read()
	report_md += page_break

with open(boilerplate_dir + 'introduction.md') as f:
	report_md += f.read()
	report_md += page_break

for file in os.listdir(findings_dir):
	filename = os.fsdecode(file)
	print(filename)
	with open(findings_dir + filename) as f:
		report_md += f.read()
		report_md += page_break

with open(boilerplate_dir + 'conclusion.md') as f:
	report_md += f.read() 
	report_md += page_break


# Insert Placeolders
report_md = report_md.format(title = config["title"], author = config["author"])


# Render Markdown: Convert to HTML
report_html = markdown.markdown(report_md)
print(report_html)


# Convert HTML to PDF
pdfkit.from_string(report_html,'report.pdf')