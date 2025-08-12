### DNS verification errors

- "DNS TXT lookup failed for domain"
  - The resolver could not fetch `_v1.agent.jacs.<domain>.` with DNSSEC. Check that DNSSEC is enabled, records are published, and DS is at registrar. Use `dig +dnssec`, `delv`, `kdig`, or `drill` to inspect.

- "DNS TXT lookup required (domain configured) or provide embedded fingerprint"
  - Strict DNS mode is active because a domain is configured. Either publish the TXT or run with `--non-strict-dns` during initial propagation.

# Error Codes
