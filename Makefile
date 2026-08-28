.PHONY: build release verify verify-fmt verify-clippy verify-test fmt e2e docker-test

build:
	cargo build --workspace

release:
	cargo build --release --workspace

fmt:
	cargo +nightly fmt --all

verify:
	bash scripts/verify.sh

verify-fmt:
	SKIP_CLIPPY=1 SKIP_TEST=1 bash scripts/verify.sh

verify-clippy:
	SKIP_FMT=1 SKIP_TEST=1 bash scripts/verify.sh

verify-test:
	SKIP_FMT=1 SKIP_CLIPPY=1 bash scripts/verify.sh

e2e: build
	bash scripts/e2e-local.sh

docker-test: release
	bash integration/cx/build-and-test.sh

docker-test-tls: release
	COMPOSE_FILE=docker-compose-tls.yml bash integration/cx/build-and-test.sh

ui-test: build
	cd integration/ui && npm ci >/dev/null 2>&1 || npm install && npx playwright install chromium && npx playwright test

vault-test: release
	bash integration/vault/build-and-test.sh
