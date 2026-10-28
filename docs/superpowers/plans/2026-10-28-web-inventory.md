# Web inventory implementation plan

Goal: make the existing web_inventory campaign stage executable on authorized HTTPS responses. Implements protocol inventory, not vulnerability detection.
Spec: docs/superpowers/specs/2026-10-28-pentest-platform-design.md.
Use inline execution and tests-first; existing user authorization covers continued implementation.

Architecture: incremental UTF-8 HTMLParser under the existing supervised HTTPS worker; no additional requests or form submissions. Capture only routes matching explicit granted paths, up to2forms/8fields per form,32raw URL references per response. Default body budget remains65536 bytes; maximum1MiB. Discard field values/raw names and query/fragment values. Hash field names; record method/type/CSRF-related-name observation, never a vulnerability verdict. Deferred base resolution includes base elements encountered after links.

Result limits: scoped routes≤8, forms≤2, fields≤8; omitted counts/unsupported encodings/truncated bodies explicitly partial. No browser DOM/JavaScript, form=id associations or crawling. Keep existing default probe behavior and audited receipt contract. Inventory uses its own operation kind and receipt mode.

Files: web_inventory.py, web_probe.py; narrow campaigns/CLI wiring; unit tests and realTLS fixture; workflow; docs.
- [ ] Commit tests, GitHub RED for missing parser/inventory option.
- [ ] Implement parser, HTTPS streaming integration and executable campaign adapter.
- [ ] Targeted tests plus full regressions Linux/Windows.
- [ ] Fresh read-only review; important fixes RED→GREEN; draft PR, no merge.

Review focus: query/value leakage, base resolution, nested/associated forms, body/record limits, result output cap, receipt isolation and default-probe compatibility. Development and tests only GitHub, synthetic fixtures, no real target traffic.
