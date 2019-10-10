# Substrate Offchain Callback Example

[![Build Status](https://dev.azure.com/benkampmann/benkampmann/_apis/build/status/gnunicorn.substrate-offchain-cb%20(1)?branchName=master)](https://dev.azure.com/benkampmann/benkampmann/_build/latest?definitionId=2&branchName=master)

This recipe shows how to build an offchain-worker that the runtime communicates with asynchronously by issuing events with callbacks the offchain worker responds to at a later point.


## Run

_Note: expects to have a full substrate checkout in `../substrate` to work_.

```bash
cargo run --release -- --dev
```

## Docs

see `docs/index.html` (or rendered here on github pages: https://gnunicorn.github.io/substrate-offchain-cb/ ) for a nicely rendered html of the inline docs explaining the runtime code.

To update this, please install [`dadada`](https://crates.io/crates/dadada) and run: `dadada --title "Substrate Offchain Worker Example" -o docs/index.html runtime/src/offchaincb.rs runtime/src/lib.rs`