dns $ jacs agent verify -a ./jacs/agent/85058eed-81b0-4eb3-878e-c58e7902c4fd\:6b2c5ddf-a07b-4e0a-af1b-b081f1b8cb32.json  --require-dns
Agent 85058eed-81b0-4eb3-878e-c58e7902c4fd:6b2c5ddf-a07b-4e0a-af1b-b081f1b8cb32 signature verified OK.
dns $ jacs agent verify -a ./jacs/agent/85058eed-81b0-4eb3-878e-c58e7902c4fd\:6b2c5ddf-a07b-4e0a-af1b-b081f1b8cb32.json  --no-dns
Agent 85058eed-81b0-4eb3-878e-c58e7902c4fd:6b2c5ddf-a07b-4e0a-af1b-b081f1b8cb32 signature verified OK.
dns $ jacs agent verify -a ./jacs/agent/85058eed-81b0-4eb3-878e-c58e7902c4fd\:6b2c5ddf-a07b-4e0a-af1b-b081f1b8cb32.json  --require-strict-dns

thread 'main' panicked at jacs/src/bin/cli.rs:691:22:
signature verification: "strict DNSSEC validation failed for _v1.agent.jacs.hai.io. (TXT not authenticated). Enable DNSSEC and publish DS at registrar"
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace