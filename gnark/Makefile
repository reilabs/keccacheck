.PHONY: run

run:
	@echo "Copying bindings.h from rust/ffi..."
	@cp ../rust/ffi/bindings.h .
	@echo "Copying libkeccak.a from target/optimized..."
	@cp ../rust/target/optimized/libkeccak.a .
	@echo "Running go clean -cache..."
	@go clean -cache