# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2022-02-09
### Added

- CHANGELOG.md

##### In struct cryptohelper::isomorphs::Pattern

- `bool operator==(const Pattern& p) const`
- `bool operator<(const Pattern& p) const`

- `size_t recalc_significance()` updates `significance` according to `v` and returns it - in case you have lost track of whether `v` and `significance` still fit together.
- `std::vector<int> to_numbers() const` returns a unified representation of the Pattern in form of numbers, e. g. `{0,1,2,0}` when `to_string()` would return `"ABCA"`.

##### In namespace cryptohelper::isomorphs

- `std::vector<size_t> find_pattern(const T& ciphertext, const Pattern& p)` searches `ciphertext` for `p` and returns the found start indices. 

### Changed

- `Pattern::significance` to type `size_t`

- `example.cpp` to a completely new Wheatstone disk example

### Fixed
- `to_pattern()`: had bad vector subscripts if `begin` != 0 *(critical)*
- `SlidingWindow::advance()` failed to classify a pattern as "filled" if the first and the last item were identical and there were no further occurrences of these, e. g. `"ABBA"` *(moderate)*

## [1.0.4] - 2022-02-05
### Fixed
- optimized the iteration in `get_isomorphs()` *(trivial)*

## [1.0.3] - 2022-02-04
### Fixed
- `get_isomorphs()`  works off now `len` from large to small and performs clean-up after each pass instead of after the loop, which should significantly reduce memory usage and increase speed *(trivial)*

## [1.0.2] - 2022-02-04
### Fixed
- `get_isomorphs()`  returned an empty map if parameter `min_length` < 2 *(moderate)*

## [1.0.1] - 2022-02-04
### Fixed
- `SlidingWindow()`  now throws an exception if parameter `len` is greater than`text.size()` *(moderate)*

## [1.0.0] - 2022-02-04

### First release