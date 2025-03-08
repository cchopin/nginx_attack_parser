# Changelog

## [1.2.0] - 2025-03-08

### Added
- Implemented IP reputation caching (valid for 30 days) to reduce the number of AbuseIPDB API calls.
- Display available log files to the user before prompting for log file selection.

### Changed
- Set default log file selection to `access.log` for improved usability.
- Improved table formatting to remove extra spaces around vertical borders for a cleaner terminal display.

### Fixed
- Fixed issue causing `UnboundLocalError` due to incorrect variable initialization order in log file selection.

