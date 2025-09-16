# Strobilus

## How to reproduce (on Linux):

Requirements: `cargo` and a Rust toolchain, `python3`, `pip` (to reproduce RQ1), `wget`, `tar` (to download `rust-code-analysis`), `jq` (for pretty printing the RQ2 JSON output).

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    wget https://github.com/mozilla/rust-code-analysis/releases/download/v0.0.25/rust-code-analysis-linux-cli-x86_64.tar.gz
    tar -xf rust-code-analysis-linux-cli-x86_64.tar.gz

    # RQ1
    cargo run --release --bin rq1
    python3 rq1.py

    # RQ2
    ./rust-code-analysis-cli -m -p crates/rq1/src/main.rs -O json | jq '.spaces.[] | select(.name == "strobilus" or .name == "cedar_local_state" or .name == "cedar_upsert") | {case: .name, cyclo: .metrics.cyclomatic.sum}'

The plot for **RQ1** will be in `rq1_plot.png`. For **RQ2** the cyclomatic complexity can be found under the `strobilus`, `cedar_local_state` and `cedar_upsert` functions summaries.
