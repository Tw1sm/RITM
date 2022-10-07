# Changelog
## [v0.1.1] - 10/6/2022
### Added
- Handling of `KDC_ERR_PREAUTH_FAILED`
- Sniffer runs within a `while` loop until a valid AS-REQ is sniffed
    - Validity tested by requesting TGS with `krbtgt` SPN 
### Fixed
- Opening/read of input `--users-file`

## [v0.1.0] - 10/5/2022
- Initial release