.PHONY: run

run:
	@echo "Copying bindings.h from rust/ffi..."
	@cp ../rust/ffi/bindings.h .
	@echo "Copying libkeccak.a from target/debug..."
	@cp ../rust/target/debug/libkeccak.a .
	@echo "Running go clean -cache..."
	@go clean -cache
	@echo "Running go run ."
	@go run . 