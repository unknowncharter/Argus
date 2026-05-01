# Argus - top-level Makefile
# Manual --root-pid flow (see daemon flags for pid-file mode).

.PHONY: deps build-bpf build-daemon build-ui run-daemon run-ui test clean

deps:
	@echo "=== Dependency hints (Ubuntu) ==="
	@echo "BPF: sudo apt-get install -y clang llvm libbpf-dev linux-headers-$$(uname -r) build-essential"
	@echo "Go:  https://go.dev/dl/ or sudo apt install golang-go"
	@echo "Node: nvm / apt install nodejs npm"
	@echo "Run the above as needed; this target does not auto-install."

build-bpf:
	$(MAKE) -C bpf

build-daemon: build-bpf
	cd daemon && go build -buildvcs=false -o daemon .

build-ui:
	cd ui && npm install

# Run daemon: use ROOT_PID=12345 (replace with actual PID)
run-daemon:
	@if [ -z "$$ROOT_PID" ]; then echo "Usage: make run-daemon ROOT_PID=<pid>"; exit 1; fi
	sudo ./daemon/daemon --root-pid $$ROOT_PID

run-ui:
	cd ui && npm run dev

test:
	cd daemon && go test -v -run 'TestProcessLineage'

clean:
	$(MAKE) -C bpf clean
	rm -f daemon/daemon
	cd ui && rm -rf .next node_modules 2>/dev/null; true
