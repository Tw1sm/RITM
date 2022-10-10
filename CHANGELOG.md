# Changelog
## [v0.1.2] - 10/9/2022
### Added
- Catch of `PermissionError` when enabling IP forwarding - basically root privs check
### Fixed
- Error when sniffed AS-REQ is one sent by the attacker during the replay
    - Now ignores AS-REQs with source IP matching the IP of the provided interface
- Error in main `finally` block if error caught before Sniffer or Spoofer creation

## [v0.1.1] - 10/6/2022
### Added
- Handling of `KDC_ERR_PREAUTH_FAILED`
- Sniffer runs within a `while` loop until a valid AS-REQ is sniffed
    - Validity tested by requesting TGS with `krbtgt` SPN 
### Fixed
- Opening/read of input `--users-file`

## [v0.1.0] - 10/5/2022
- Initial release