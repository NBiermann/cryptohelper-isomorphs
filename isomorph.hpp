#pragma once

#include <map>
#include <vector>
#include <string>

namespace cryptohelper {

struct isomorph_pattern {
	std::vector<size_t> v;
	int significance = 0;

	isomorph_pattern() = default;
	isomorph_pattern(size_t n) : v(n), significance(0) {}
	size_t size() const {return v.size();}
	std::string to_string() const {
		const char nullchar = '?';
		std::string s(v.size(), nullchar);
		char ch = 'A';
		for (size_t i = 0; i != v.size(); ++i) {
			if (s[i] != nullchar) continue;
			if (ch == 'z' + 1) return ("<pattern too complex>");
			if (ch == 'Z' + 1) ch = 'a';
			s[i] = ch;
			size_t j = i;
			while (v[j]) {
				j += v[j];
				s[j] = ch;
			}
			++ch;
		}
		return s;
	}
	bool is_part_of(const isomorph_pattern& pat) const {
		if (v.size() > pat.v.size()) return false;
		if (v.size() == pat.v.size()) return v == pat.v;
		for (size_t offset = 0; offset + v.size() <= pat.v.size(); ++offset) {
			bool match = true;
			for (size_t i = 0; i != v.size(); ++i) {
				if (v[i] == pat.v[offset + i]) continue;
				if (v[i]) {
					match = false;
					break;
				}
				if (i + pat.v[offset + i] >= v.size()) continue;
				match = false;
				break;
			}
			if (match) return true;
		}
		return false;
	}
};

// comparator - the returned map is to be ordered by 
// descending size and descending significance of the patterns
struct isomorph_pattern_gt {
	bool operator()(const isomorph_pattern& p1, 
					const isomorph_pattern& p2) const {
		if (p1.size() != p2.size())
			return p1.size() > p2.size();
		if (p1.significance != p2.significance)
			return p1.significance > p2.significance;
		return p1.v < p2.v;
	}
};

// Returns the found patterns mapped to a vector<size_t> of their starting
// positions in the ciphertext. Patterns that only occur once are ignored.
// Patterns that actually are sub-patterns of longer ones in the result map 
// are ignored, unless they occur at more places than their "parents". 
// The ciphertext type T may be a string or vector of any type. The template
// makes use of T::size(), T::at() and T::value_type::operator==(). 
template<class T>
std::map<isomorph_pattern, std::vector<size_t>, isomorph_pattern_gt>
	get_isomorph_patterns(
		const T& ciphertext,
		size_t min_length = 3,
		size_t max_length = -1,
		size_t min_significance = 2)
{
	if (!max_length) max_length = ciphertext.size() / 2;
	std::map<isomorph_pattern, std::vector<size_t>, 
							   isomorph_pattern_gt> result;
	if (min_length < 2) return result;
	for (size_t len = min_length; len <= max_length; ++len) {
		// a pattern longer than half the ciphertext size can't repeat
		if (len > ciphertext.size() / 2) break;
		// initialize pattern at the beginning of the ciphertext
		isomorph_pattern pat(len);
		// keep track of whether the last item is a repetition, i. e. is
		// referenced (= pointed to) somewhere in v
		bool last_item_is_referenced = false;
		for (size_t i = 0; i != len - 1; ++i) {
			for (size_t j = i + 1; j != len; ++j) {
				if (ciphertext.at(i) == ciphertext.at(j)) {
					pat.v[i] = j - i;
					++pat.significance;
					if (j == len - 1) last_item_is_referenced = true;
					break;
				}
			}
		}
		size_t pos = 0;
		while (1) {
			// if the first value of v is non-zero and the last item is
			// referenced, then the actual pattern size equals len:
			// add pattern to result map
			if (pat.significance >= min_significance &&
				pat.v[0] && last_item_is_referenced) {
				result[pat].push_back(pos);
			}
			if (pos + len == ciphertext.size()) break;
			// move sliding window forward
			++pos;
			// remove first item
			if (pat.v[0]) --pat.significance;
			pat.v.erase(pat.v.begin());
			// insert zero at the end
			pat.v.push_back(0);
			// search for the newly arrived value
			last_item_is_referenced = false;
			auto val = ciphertext.at(pos + len - 1);
			for (size_t diff = 1; diff != len; ++diff) {
				if (ciphertext.at(pos + len - 1 - diff) == val) {
					pat.v[len - 1 - diff] = diff;
					++pat.significance;
					last_item_is_referenced = true;
					break;
				}
			}
		}
	}
	// delete patterns with only 1 occurence:
	auto it = result.begin();
	while (it != result.end()) {
		if (it->second.size() < 2) it = result.erase(it);
		else ++it;
	}
	// delete any pattern that is contained in another (longer) pattern unless 
	// it has more occurences than the latter
	auto it1 = result.begin();
	while (it1 != result.end()) {
		bool is_contained = false;
		for (auto it2 = result.begin(); it2 != result.end(); ++it2) {
			// patterns are sorted by descending size in the map
			if (it1->first.size() >= it2->first.size()) break;
			if (it1->first.is_part_of(it2->first) &&
					it1->second.size() == it2->second.size()) {
				is_contained = true;
				break;
			}
		}
		if (is_contained) it1 = result.erase(it1);
		else ++it1;
	}
	return result;
}
} // namespace cryptohelper
