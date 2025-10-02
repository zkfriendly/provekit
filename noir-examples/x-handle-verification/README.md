nargo execute && bb prove -b ./target/link_x_handle_command.json -w ./target/link_x_handle_command.gz -o ./target

cargo run --release --bin provekit-cli prepare ./target/link_x_handle_command.json -o ./target/scheme.nps

hyperfine '../../target/release/provekit-cli prove ./target/scheme.nps ./Prover.toml' 'nargo execute && bb prove -b ./target/link_x_handle_command.json -w ./target/link_x_handle_command.gz -o ./target' --show-output