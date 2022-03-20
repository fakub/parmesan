# build-only
build:
	RUSTFLAGS="-C target-cpu=native" cargo build --release

# run tests
test:
	RUSTFLAGS="-C target-cpu=native" cargo test --release
