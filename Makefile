# flowtrace — developer targets. Every target runs the same commands the CI
# workflow (.github/workflows/gate.yml) runs, so a green `make check` here
# is a green `three-repo` job there.
#
# SIBLINGS: where the companion checkouts live (default: beside this repo).
# Until azimuth-ink/polydiagram@ce3598f and azimuth-ink/agent-dec@05874ca are
# pushed, `make dev` installs both from those local checkouts instead of the
# pinned git refs in pyproject.toml [companions]. Both are installed as wheels
# (pip builds them from the checkout); never `pip install -e` a companion — an
# editable install of agent-dec resolves its default methods directory
# relative to the checkout and masks the installed-package behaviour CI sees.
SIBLINGS ?= $(abspath ..)
PY ?= python3
PIP_FLAGS ?= --break-system-packages
FLOWS = examples/flows
TEL = examples/telemetry
GATE_ARGS = --flows $(FLOWS) --config flowtrace.yaml --alerts examples/alerts.yaml \
            --queries examples/queries/quote-issue.queries.yaml \
            --trust-bundle examples/dec/trust-bundle.json --dec-dir examples/dec/flow-bound \
            --execution-evidence --reproducible
# the seven synthetic windows: three pass the gate, four must fail it
PASSING = full s5-degraded s6-unknown-reconciled
FAILING = s5-silent s4-missing-attr s6-retry-unreconciled cancelled-child-late
WINDOWS = $(PASSING) $(FAILING)
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

verify-dec:     ## agent-dec's verifier over its flow-bound example and the vendored copy, with flowtrace's flows as the registry
	dec-verify --dir "$(SIBLINGS)/agent-dec/examples/flow-bound" --methods "$(SIBLINGS)/agent-dec/examples/methods" \
	           --trust-bundle "$(SIBLINGS)/agent-dec/examples/trust-bundle.json" --flow-registry $(FLOWS) --require-convergent
	dec-verify --dir examples/dec/flow-bound --methods examples/dec/methods --trust-bundle examples/dec/trust-bundle.json \
	           --flow-registry $(FLOWS) --require-convergent

gate:           ## the seven windows (three pass; the other four must fail)
	mkdir -p $(OUT)
	flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.full.otlp.jsonl --out $(OUT)/quote-issue.full.json
	flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.s5-degraded.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.s5-degraded.json
	flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.s6-unknown-reconciled.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.s6-unknown-reconciled.json
	! flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.s5-silent.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.s5-silent.json
	! flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.s4-missing-attr.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.s4-missing-attr.json
	! flowtrace gate $(GATE_ARGS) --telemetry $(TEL)/quote-issue.s6-retry-unreconciled.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.s6-retry-unreconciled.json
	! flowtrace gate $(GATE_ARGS) --runs-dir examples/dec/flow-bound/negative/cancellation-not-propagated \
	    --telemetry $(TEL)/quote-issue.cancelled-child-late.otlp.jsonl --baseline $(OUT)/quote-issue.full.json --out $(OUT)/quote-issue.cancelled-child-late.json

expected: gate  ## regenerate examples/expected from the current engine (review the diff!)
	@for w in $(WINDOWS); do cp $(OUT)/quote-issue.$$w.json examples/expected/quote-issue.$$w.json; done

check-expected: gate  ## the gate reproduces the committed expected reports byte for byte
	@for w in $(WINDOWS); do cmp $(OUT)/quote-issue.$$w.json examples/expected/quote-issue.$$w.json && echo "identical: quote-issue.$$w.json"; done

check: test validate-flows verify-dec check-expected  ## everything the three-repo CI job runs

clean:
	rm -rf build .pytest_cache .hypothesis dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
