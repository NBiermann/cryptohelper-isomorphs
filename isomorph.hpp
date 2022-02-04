#pragma once

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptohelper {

namespace isomorphs {

struct Pattern {
    std::vector<size_t> v;
    int significance = 0;

    Pattern() = default;
    Pattern(size_t n) : v(n), significance(0) {}

    size_t size() const { return v.size(); }

    std::string to_string() const {
        const char nullchar = '?';
        std::string s(v.size(), nullchar);
        char ch = 'A';
        for (size_t i = 0; i != v.size(); ++i) {
            if (s[i] != nullchar)
                continue;
            if (ch == 'z' + 1)
                return ("<Pattern too complex>");
            if (ch == 'Z' + 1)
                ch = 'a';
            s[i] = ch;
            size_t j = i;
            while (v[j]) {
                j += v[j];
                if (j >= v.size())
                    throw std::runtime_error(
                        "Pattern::to_string(): ill-formed pattern");
                s[j] = ch;
            }
            ++ch;
        }
        return s;
    }

    bool is_part_of(const Pattern& pat) const {
        if (v.size() > pat.v.size())
            return false;
        if (v.size() == pat.v.size())
            return v == pat.v;
        for (size_t offset = 0; offset + v.size() <= pat.v.size(); ++offset) {
            bool match = true;
            for (size_t i = 0; i != v.size(); ++i) {
                if (v[i] == pat.v[offset + i])
                    continue;
                if (v[i]) {
                    match = false;
                    break;
                }
                if (i + pat.v[offset + i] >= v.size())
                    continue;
                match = false;
                break;
            }
            if (match)
                return true;
        }
        return false;
    }
};

template <class T>
Pattern to_pattern(T text, size_t begin = 0, size_t end = -1) {
    if (end > text.size())
        end = text.size();
    if (begin >= end)
        return Pattern(0);
    Pattern pat(end - begin);
    for (size_t i = begin; i != end - 1; ++i) {
        for (size_t j = i + 1; j != end; ++j) {
            if (text.at(i) == text.at(j)) {
                pat.v[i] = j - i;
                ++pat.significance;
                break;
            }
        }
    }
    return pat;
}

template <class T>
class SlidingWindow {
    const T& text;
    size_t offset;
    size_t len;
    Pattern pat;
    bool is_first_item_repeated = false;
    bool is_last_item_repeated = false;

   public:
    SlidingWindow(const T& t, size_t l) : text(t), offset(0), len(l) {
        if (len < 2)
            throw std::runtime_error(
                "SlidingWindow(): cannot initialize with length < 2");
        pat = to_pattern<T>(text, 0, len);
        if (pat.size() < len)
            throw std::runtime_error(
                "SlidingWindow(): text too short, cannot initialize");
        is_first_item_repeated = pat.v[0];
        auto val = text.at(len - 1);
        for (size_t i = len - 2; i != 0; --i) {
            if (text.at(i) == val) {
                is_last_item_repeated = true;
                break;
            }
        }
    }

    // returns true if successful, false if at end of text
    bool advance() {
        if (offset + len == text.size())
            return false;
        ++offset;
        // remove first item in pattern
        if (pat.v[0])
            --pat.significance;
        pat.v.erase(pat.v.begin());
        // insert zero at the end
        pat.v.push_back(0);
        is_first_item_repeated = pat.v[0];
        // search for the newly included value
        is_last_item_repeated = false;
        auto val = text.at(offset + len - 1);
        for (size_t diff = 1; diff != len; ++diff) {
            if (text.at(offset + len - 1 - diff) == val) {
                pat.v[len - 1 - diff] = diff;
                ++pat.significance;
                is_last_item_repeated = true;
                break;
            }
        }
        return true;
    }

    const Pattern& get_pattern() const { return pat; }

    size_t get_offset() const { return offset; }

    // returns true if both the first and last character are repeated 
    // somewhere within the window. Otherwise the effective pattern is of
    // smaller size than the window.
    bool is_filled() const {
        return is_first_item_repeated && is_last_item_repeated;
    }
};

// comparator - the patterns of the map returned by get_isomorphs() are to
// be ordered by 1) descending size, 2) descending significance, 3) ascending
// built-in vector order of v
struct pattern_comp {
    bool operator()(const Pattern& p1, const Pattern& p2) const {
        if (p1.size() != p2.size())
            return p1.size() > p2.size();
        if (p1.significance != p2.significance)
            return p1.significance > p2.significance;
        return p1.v < p2.v;
    }
};

// Returns the found patterns mapped to a vector<size_t> of their start
// positions in the ciphertext. Patterns that only occur once are ignored.
// Patterns that actually are sub-patterns of longer ones in the result map
// are ignored, unless they occur at more places than their "parents".
// The ciphertext type T may be a string or vector of any type. The template
// makes use of T::size(), T::at() and T::value_type::operator==().
template <class T>
std::map<Pattern, std::vector<size_t>, pattern_comp> get_isomorphs(
    const T& ciphertext,
    size_t min_length = 3,
    size_t max_length = -1,
    size_t min_significance = 2) {
    if (!min_length)
        min_length = min_significance + 1;
    // a pattern longer than half the ciphertext can't repeat
    if (max_length > ciphertext.size() / 2)
        max_length = ciphertext.size() / 2;
    std::map<Pattern, std::vector<size_t>, pattern_comp> result;
    if (min_length >= ciphertext.size())
        return result;
    for (size_t len = max_length; len >= min_length; --len) {
        // initialize sliding window at the beginning of the ciphertext
        SlidingWindow<T> win(ciphertext, len);
        do {
            // if preconditions are met, add pattern to result map
            Pattern pat = win.get_pattern();
            if (pat.significance >= min_significance && win.is_filled())
                result[pat].push_back(win.get_offset());
        } while (win.advance());
        // clean-up
        auto it = result.begin();
        while (it != result.end() && it->first.size() != len)
            ++it;     
        while (it != result.end()) {
            // delete patterns with only 1 occurence:
            if (it->second.size() < 2) {
                it = result.erase(it); 
                continue;
            }
            // delete any pattern that is contained in another (longer) pattern
            // unless it has more occurences than the latter
            bool is_contained = false;
            for (auto it2 = result.begin(); it2 != result.end(); ++it2) {
                // patterns are sorted by descending size in the map
                if (it2->first.size() == len)
                    break;
                if (it->first.is_part_of(it2->first) &&
                    it->second.size() <= it2->second.size()) {
                    is_contained = true;
                    break;
                }
            }
            if (is_contained)
                it = result.erase(it);
            else
                ++it;
        }
    }
    return result;
}

}  // namespace isomorphs

}  // namespace cryptohelper
