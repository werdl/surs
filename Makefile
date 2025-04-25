ARGS ?=

default: debug run

debug:
	cargo build

# oh the irony
	sudo chown root:root target/debug/surs
	sudo chmod 4755 target/debug/surs

release:
	cargo build --release
	sudo chown root:root target/release/surs
	sudo chmod 4755 target/release/surs

run:
	./target/debug/surs $(ARGS)

clean:
	cargo clean
	sudo rm -f target/debug/surs
	sudo rm -f target/release/surs
