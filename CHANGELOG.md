# Changelog

## [1.2.2] - 2025-03-08

### Fixed
- Sort log file list display by date (newest first)

## [1.2.1] - 2025-03-08

### Fixed
- Fixed bug in IP reputation cache system that was causing redundant API calls despite cached data being available
- Removed duplicate function `clean_old_cache_entries`
- Eliminated redundant `save_cache_to_file` function

### Enhanced
- Improved table formatting with consistent vertical borders and proper box-drawing characters
- Added sorting to the log file list display (alphabetical order)
- Refactored `generate_report` function to properly use the cache parameter
- Streamlined the main function flow to avoid redundant API key and cache loading


## [1.2.0] - 2025-03-08

### Added
- Implemented IP reputation caching (valid for 30 days) to reduce the number of AbuseIPDB API calls.
- Display available log files to the user before prompting for log file selection.

### Changed
- Set default log file selection to `access.log` for improved usability.
- Improved table formatting to remove extra spaces around vertical borders for a cleaner terminal display.

### Fixed
- Fixed issue causing `UnboundLocalError` due to incorrect variable initialization order in log file selection.

