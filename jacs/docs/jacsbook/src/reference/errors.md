### DNS verification errors

- "strict DNSSEC validation failed for <owner> (TXT not authenticated). Enable DNSSEC and publish DS at registrar"
  - DNSSEC mode was requested but the TXT response wasn’t authenticated. Enable DNSSEC for the zone and publish the DS at the registrar.

- "DNS TXT lookup failed for <owner> (record missing or not yet propagated)"
  - Non-strict lookup could not fetch the TXT. Wait for propagation or confirm the record name/value.

- "DNS TXT lookup required (domain configured) or provide embedded fingerprint"
  - Strict DNS mode is active because a domain is configured. Either publish the TXT or run with `--non-strict-dns` during initial propagation.

# Error Codes
