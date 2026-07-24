# Synthetic samples

**All events in this directory are synthetic.** They were hand-authored to
exercise the detection rules and contain no real users, keys, IPs, or captured
traffic. IP addresses use the documentation ranges reserved by RFC 5737
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); `api_key_id` values are
fake placeholder hashes.

Each `*_malicious.jsonl` file should be fully matched by its rule, and each
`*_benign.jsonl` file should be fully ignored by it. `tests/test_sigma_matches.py`
enforces both directions.
