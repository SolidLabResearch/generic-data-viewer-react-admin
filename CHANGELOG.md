# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The possibility to add templated queries with indirect variables (#78).

### Changed

- Refactoring: isolated the Comunica engine with accompanying operations into a wrapper class (#152).
- Updated the README.md with documentation for the indirect variables (#78).

### Fixed

- Correct error display when the queryLocation is a non existing file or faultive (#147).
- Fixed a bug where editing a custom query did not correctly remove unchecked options (#150).

## [1.2.3] - 2024-07-11

### Added

- A group of generic query examples was added (#135).
- Some icons for well known query groups were added (#146).

## [1.2.2] - 2024-06-27

### Added

- It is now possible to add and edit custom queries (#54).

### Changed

- For logged in users not having a username, the webID is displayed (#133).
- Automatic detection of Identity Provider or webID in login screen (#67).

### Fixed

- Forced CSS's to not return content type application/ld+json, which induced a CORS error on some CSS server versions (#131).
- Queries based on index file now work for any variable, not just ?object (#136).
- Queries based on index file now work for index files requiring authentication (#139).

## [1.2.1] - 2024-06-17

### Added

- Added a single point of access to the config.json file (#32).

### Changed

- Removed the display "Loaded: x results" in the action bar to avoid confusion (#83).

### Fixed

- Fixed the broken production version due to a missing package (#123).
- Corrected the counting of the total number of items in the result list (#120).
- Avoided extending query objects in the configuration (#126).

## [1.2.0] - 2024-05-07

### Added

- "Clear query cache and refresh" button (#105).
- Source verification effective code (#77).
- Query can now also be based on index file (#91).
- Added collapsible query groups to the menu on the left (#89).

### Changed

- Clear query cache at logout (#106).
- Cypress test suite version updated to ^13.8.0 (#109).
- Hovering over query menu now displays a tooltip with information instead of expanding inside the menu (#112).

### Fixed

- Query menu is now scrollable (#102).
- Pagination is correct when using a query using DISTINCT, OFFSET, LIMIT (#110, #19).

### Removed

## [1.1.3] - 2024-04-04

### Added

- Added 'Unauthorized' to the fetch status (#90).
- Query title above the result table (#41).

### Changed

- On empty query result, show clear message (#86).
- Force accept headers to favor NQuads to remove JSON-LD Context CORS issue problems (#100).

### Fixed

- Fixed pagination bug in templated queries (#80).
- Fixed title display inside the selection menu when hovering, does not flow over table anymore (#41).

### Removed

## [1.1.2] - 2024-03-13

### Added

- Source verification stub code (#73).

### Changed

### Fixed

- Invalidate query engine cache on user logout (#63).

### Removed

## [1.1.1] - 2024-01-30

### Added

### Changed

- URLs open in a new browser tab now (#81).

### Fixed

- Aggregating SPARQL queries work now (#70).
- Sources' fetch status is consistent now (#59).

### Removed

## [1.1.0] - 2024-01-22

### Added

- Configurable query icons (#9).
- "Username not given" when logged in, but user's name not known (#51, #65).
- Templated query functionality (#52).

### Changed

- Changed loading message to "The page is loading. Just a moment please." (#26).
- Enabled no bad blocks and indentation for eslint/jsdoc (#14).

### Fixed

- Configured title is now also visible before first query (#46).

### Removed

- Bulk action checkboxes are removed (#44).

## [1.0.0] - 2023-09-13

### Added

- First release

[1.0.0]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.0.0
[1.1.0]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.1.0
[1.1.1]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.1.1
[1.1.2]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.1.2
[1.1.3]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.1.3
[1.2.0]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.2.0
[1.2.1]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.2.1
[1.2.2]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.2.2
[1.2.3]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.2.3
[Unreleased]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/compare/v1.2.3...HEAD
