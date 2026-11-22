# Security policy

poisonscan scans hostile content by design. Reports of detection bypasses and of
bugs in the engine itself are welcome.

## Reporting

- **Detection bypasses and engine vulnerabilities** (crash, excessive CPU or memory on
  crafted input, anything that lets scanned content act on the host): report them
  privately through GitHub's **"Report a vulnerability"** button (Security tab,
  private vulnerability reporting). Do not open a public issue.
- Include a minimal sample, preferably synthetic, using reserved domains
  (`example.test`, `example.com`). Never send real personal data or real secrets.
- Plain false positives are not security issues: open a regular issue or a pull
  request with a negative test example (see CONTRIBUTING.md).

## What to expect

- Acknowledgement within 7 days.
- A fixed bypass becomes a rule change or a new rule, with the sample added to the
  test corpus once the fix is released.

## Supported versions

Only the latest release and the `main` branch receive fixes.
