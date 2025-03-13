# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support for multiple configurations (#69, #49).
- Collections of known configurations are gathered in subdirectories of main/configs (#175).
- Templated queries: variables shown in title of result table (#163).
- Templated queries: changing variables dialogue is preloaded with previous values (#167).
- About dialog, reachable from the application bar (#171).

## [1.5.0] - 2025-01-02

### Added

- Templated queries variables selection made easier with filters (#172).

## [1.4.1] - 2024-10-16

### Fixed

- Templated queries now also work for queries containing multiple occurrences of a template variable (#164).
- Works when served from any base URL including a path (e.g. `https://www.example.com/your/preferred/path`) (#165).
- Corrected the link created from a custom query's SHARE QUERY button for the case where the base URL includes a path (#169).

## [1.4.0] - 2024-10-02

### Added

- The possibility to save and load custom queries to and from a pod (#140).

## [1.3.1] - 2024-08-27

### Added

- The possibility to create a custom query from an existing query and to clone a custom query (#141).

### Changed

- Split directories to isolate the site code (main) from the test and development tools (test) (#157).
- Sources from index file(s) (aka indirect sources) now works recursively, using the Comunica link-traversal feature (#79).

## [1.3.0] - 2024-08-07

### Added

- Templated queries can now have values for variables as a result of a query ("Indirect variables") (#78).

### Changed

- Refactoring: isolated the Comunica engine with accompanying operations into a wrapper class (#152).

### Fixed

- Correct error display when the queryLocation is a non existing file or faulty (#147).
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
[1.3.0]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.3.0
[1.3.1]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.3.1
[1.4.0]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.4.0
[1.4.1]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.4.1
[1.5.0]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/releases/tag/v1.5.0
[Unreleased]: https://github.com/SolidLabResearch/generic-data-viewer-react-admin/compare/v1.5.0...HEAD
