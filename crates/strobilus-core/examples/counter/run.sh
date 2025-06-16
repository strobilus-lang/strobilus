#!/bin/bash
cargo run -- -p 'User::"max"' -a 'Action::"view"' -r 'File::"42"' --policy-path policy.cedar --rules-path rules.strobilus
