# Changelog

The version is in the `VERSION` file and shown in the page footer. It follows semantic versioning,
MAJOR.MINOR.PATCH:

- **MAJOR:** a change to how the app fundamentally works, or one that changes what operators or
  administrators must configure (new required settings, a different way of building or checking logs).
- **MINOR:** a new feature or a noticeable improvement, with existing setups still working as before.
- **PATCH:** a fix, documentation, or a small adjustment to existing behaviour.

Every change merged into `main` raises the version, and each release is tagged `vX.Y.Z` in GitHub.
Versions before 2.2.0 were assigned afterwards, from the merges in the git history.

## 2.2.0 (2026-11-16)
- **Missing data panel:** for a rule a single generated log can't fire, the operator picks example values
  or enters their own. Covers `correlate()` rules (with companion events built for each other source,
  sharing the chosen value), `ioc:lookup()` (real indicators listed from Falcon Intelligence),
  lookup files, aggregation thresholds, and any unmet condition.
- Correlate rule samples are built from their own sub-search and labelled "Needs more events".
- Build version shown in the page footer, with this changelog.

## 2.1.1 (2026-11-16)
- Proofpoint samples rebuilt from the SIEM API documentation: delivered, click and blocked events, with
  obviously synthetic threat IDs and dashboard links, and lower-case `threatType` and `classification`.

## 2.1.0 (2026-11-16)
- Parser field catalog for every tenant parser; timestamp format checks; samples repaired to carry
  parseable, current timestamps; timezones taken from the system where a parser needs one.

## 2.0.0 (2026-11-13)
- Rule check and rule samples built on a simulation of each connector's real parser (needs NGSIEM
  Parsers: Read). Word-based sample search, scheduled rule refresh, Verify in NG-SIEM, accepting
  suggestions.

## 1.5.0 (2026-11-10)
- Security fixes from the penetration test: operator login, host allowlist, password lockout, Falcon API
  rate limits, Content-Security-Policy.

## 1.4.0 (2026-11-09)
- `HOST` setting for client/server deployments. HOW-TO guide with screenshots.

## 1.3.1 (2026-11-09)
- Sample logs and the rule check aligned with the tenant's parsers.

## 1.3.0 (2026-11-09)
- Configured rules load first, scrollable dropdowns, application settings (title, logo, contact).

## 1.2.0 (2026-11-09)
- Correlation rule templates, live rule check, and the warning before rules fire.

## 1.1.0 (2026-11-05)
- Pull connector support and built-in sample events.

## 1.0.0 (2026-11-01)
- First release: send a raw log through a clone of an NG-SIEM data connector.
