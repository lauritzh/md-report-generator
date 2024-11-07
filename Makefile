.PHONY: init all findings view-findings

init:
	python3 -m venv venv
	./run_in_venv.sh pip3 install -r ./requirements.txt

all:
	./run_in_venv.sh python3 generate.py --all

findings:
	./run_in_venv.sh python3 generate.py --findings_only

view-findings:
	./run_in_venv.sh python3 generate.py --view_findings
