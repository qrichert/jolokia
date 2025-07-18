ERROR := \x1b[0;91m
INFO := \x1b[0;94m
NC := \x1b[0m

define show_help_message
	echo "Usage: make TARGET"
	echo ""
	echo "Commands:"
	grep -hE '^[A-Za-z0-9_ \-]*?:.*##.*$$' $(MAKEFILE_LIST) | \
	    awk 'BEGIN {FS = ":.*?## "}; {printf "  $(INFO)%-12s$(NC) %s\n", $$1, $$2}'
endef

define show_error_message
	echo "$(ERROR)[Error] $(1)$(NC)"
endef

PREFIX ?= /usr/local

.PHONY: all
all: build

.PHONY: help
help: ## Show this help message
	@$(show_help_message)

.PHONY: clean
clean: ## Clean project files
	@cargo clean

.PHONY: r
r: run
.PHONY: run
run: ## Build and run program
	@cargo run --quiet --all-features

.PHONY: b
b: build
.PHONY: build
build: ## Make optimized release build
	@cargo build --release --all-features

.PHONY: l
l: lint
.PHONY: lint
lint: ## Run various linting tools
	@pre-commit run --all-files

.PHONY: check
check: ## Most stringent checks (includes checks still in development)
	@rustup update || :
	@cargo fmt
	@cargo doc --no-deps --all-features
	@cargo check
	@cargo clippy --all-targets --all-features -- -D warnings -W clippy::all -W clippy::cargo -W clippy::complexity -W clippy::correctness -W clippy::nursery -W clippy::pedantic -W clippy::perf -W clippy::style -W clippy::suspicious -A clippy::missing-const-for-fn -A clippy::multiple_crate_versions -A clippy::option_if_let_else
	@make lint
	@make test
	@make coverage-pct

.PHONY: t
t: test
.PHONY: test
test: ## Run unit tests
	@cargo test --all-features

.PHONY: doc
doc: ## Build documentation
	@cargo doc --all-features --document-private-items
	@echo file://$(shell pwd)/target/doc/$(shell basename $(shell pwd))/index.html

.PHONY: c
c: coverage
.PHONY: coverage
coverage: ## Unit tests coverage report
	@cargo tarpaulin --engine Llvm --timeout 120 --skip-clean --out Html --output-dir target/ --all-features
	@echo file://$(shell pwd)/target/tarpaulin-report.html

.PHONY: cpc
cpc: coverage-pct
.PHONY: coverage-pct
coverage-pct: ## Ensure code coverage minimum %
	@cargo tarpaulin --engine Llvm --timeout 120 --out Stdout --all-features --fail-under 75

.PHONY: install
install: ## Install cronrunner
	install -d $(PREFIX)/bin/
	install ./target/release/jolokia $(PREFIX)/bin/jolokia

.PHONY: ci-bin-name
ci-bin-name:
	@echo "jolokia"

%:
	@$(call show_error_message,Unknown command '$@')
	@$(show_help_message)
