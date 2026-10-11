# flowtrace — developer targets. Every target runs the same commands the CI
# workflow (.github/workflows/gate.yml) runs, so a green `make check` here
# is a green `three-repo` job there.
#
# SIBLINGS: where the companion checkouts live (default: beside this repo).
# Until azimuth-ink/polydiagram@9345577 and azimuth-ink/agent-dec@e8075f9 are
# pushed, `make dev` installs both from those local checkouts instead of the
# pinned git refs in pyproject.toml [companions].
SIBLINGS ?= $(abspath ..)
PY ?= python3
PIP_FLAGS ?= --break-system-packages
FLOWS = examples/flows
TEL = examples/telemetry
GATE_ARGS = --flows $(FLOWS) --config flowtrace.yaml --alerts examples/alerts.yaml \
            --queries examples/queries/quote-issue.queries.yaml \
            --trust-bundle examples/dec/trust-bundle.json --dec-dir examples/dec/flow-bound \
            --execution-evidence --reproducible
WINDOWS = full s5-silent s4-missing-attr
OUT ?= build/reports

.PHONY: dev dev-pinned test validate-flows verify-dec gate expected check-expected check clean

dev:            ## install flowtrace (editable) + companions from sibling checkouts + dev deps
	$(PY) -m pip install $(PIP_FLAGS) -r requirements-dev.txt
	$(PY) -m pip install $(PIP_FLAGS) "$(SIBLINGS)/polydiagram" "$(SIBLINGS)/agent-dec"
	$(PY) -m pip install $(PIP_FLAGS) -e .

dev-pinned:     ## the same, from the pinned git refs (once they are pushed)
	$(PY) -m pip install $(PIP_FLAGS) -r requirements-dev.txt
	$(PY) -m pip install $(PIP_FLAGS) -e ".[companions]"

test:
	$(PY) -m pytest -q

validate-flows: ## polydiagram's validator (R1–R11, --strict) over examples/flows
	polydiagram-flows --dir $(FLOWS) --strict

verify-dec:     ## agent-dec's verifier over its flow-bound example, with flowtrace's flows as the registry
	dec-verify --dir "$(SIBLINGS)/agent-dec/examples/flow-bound" --methods "$(SIBLINGS)/agent-dec/examples/methods" --flow-registry $(FLOWS) --require-convergent
	dec-verify --dir examples/dec/flow-bound --methods examples/dec/methods --trust-bundle examples/dec/trust-bundle.json --require-convergent

gate:           ## the three windows (full passes; the other two must fail)
	mkdir -p $(OUT)
	flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.full.otlp.jsonl --out $(OUT)/quote-issue.full.json
	! flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.s5-silent.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.s5-silent.json
	! flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.s4-missing-attr.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.s4-missing-attr.json

expected: gate  ## regenerate examples/expected from the current engine (review the diff!)
	cp $(OUT)/quote-issue.full.json examples/expected/quote-issue.full.json
	cp $(OUT)/quote-issue.s5-silent.json examples/expected/quote-issue.s5-silent.json
	cp $(OUT)/quote-issue.s4-missing-attr.json examples/expected/quote-issue.s4-missing-attr.json

check-expected: gate  ## the gate reproduces the committed expected reports byte for byte
	@for w in $(WINDOWS); do cmp $(OUT)/quote-issue.$$w.json examples/expected/quote-issue.$$w.json && echo "identical: quote-issue.$$w.json"; done

check: test validate-flows verify-dec check-expected  ## everything the three-repo CI job runs

clean:
	rm -rf build .pytest_cache .hypothesis dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
