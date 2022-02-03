### Cryptohelpers

As a big fan of classical ciphers and computer algorithms for solving them, I have developed several tools over the last years to help solving crypto problems. Most of them are written in C++, some of which I am now publishing on GitHub.

### Isomorphs

are fragments in the ciphertext whose structure is exactly repeated, which means if two positions in sequence A hold the same letter, the corresponding positions in sequence B do the same, and vice versa. For example:

```
...wqiqswazzrq... (somewhere in the ciphertext)
...pasatpybbqa... (somewhere else in the ciphertext)
   12 2 1 33 2
```

See also the paper ["Analysis of a late 19th century french cipher created by Major Josse"](https://www.tandfonline.com/doi/full/10.1080/01611194.2021.1996484) by George Lasry.
In January 2022, George created a [challenge](https://scienceblogs.de/klausis-krypto-kolumne/the-friedman-ring-challenge-by-george-lasry/) which can only be solved by identifying the isomorphs and using them to reduce the possible ciphertext alphabets of a Wheatstone Disk to a small number. 

This led me to write an algorithm that recognizes isomorphs in a given ciphertext. It is a template and accepts as ciphertext a `std::string` as well as a `std::vector` of any comparable type.

### Overview

```c++
namespace cryptohelper {
namespace isomorphs {

struct Pattern {
    std::vector<size_t> v;
    int significance = 0;

    Pattern() = default;
    Pattern(size_t n) : v(n), significance(0) {}
    size_t size() const {return v.size();}
    std::string to_string() const;
    bool is_part_of(const Pattern& pat) const;
};

template<class T>
Pattern to_pattern(T text, size_t begin = 0, size_t end = -1);

template<class T>
class SlidingWindow {
public:
    // initialize at the beginning of a text
    SlidingWindow(const T& text, size_t length); 
    // returns true if successful, false if at end of text
    bool advance();
    const Pattern& get_pattern() const;
    size_t get_offset() const;
    // returns if both the first and last character are repeated
    // somewhere within the window. Otherwise the effective pattern is
    // of smaller size than the window.
    bool is_filled() const;
};

// Returns the found patterns mapped to a vector<size_t> of their start
// positions in the ciphertext. The patterns are sorted by descending size
// and descending significance. Patterns that only occur once are ignored.
// Patterns that actually are sub-patterns of longer ones in the result map 
// are ignored, unless they occur at more places than their "parents". 
// The ciphertext type T may be a string or vector of any type. The template
// makes use of T::size(), T::at() and T::value_type::operator==(). 
template<class T>
std::map<Pattern, std::vector<size_t>>
    get_isomorphs(const T& ciphertext,
                  size_t min_length = 3,
                  size_t max_length = -1,
                  size_t min_significance = 2);

} // namespace cryptohelper::isomorphs
} // namespace cryptohelper
```

The "significance" of a pattern is defined as
*[number of occurences of repeated characters] - [number of disctinct repeated characters]*. 

In the above given example the sequences have 7 positions with repeated letters and 3 different such letters, thus a significance of 7 - 3 = 4.

##### Internal representation of an isomorph pattern

The vector `Pattern::v` represents a pattern in the following way: For each letter, the value at the corresponding index indicates after how many positions the same letter reappears for the first time. This approach eases the implementation of an efficient "sliding window".

If we take the first 15 letters of George Lasry's challenge as an example, v looks like this

```
S  H  C  O  E  N  S  Q  Q  V  T  Z  Z  O  I ...
6  0  0 10  0  0  0  1  0  0  0  1  0  0  0
```

Note that the pattern's significance can be read out as the number of non-zero values.

When moving the "sliding window" one position forward in the ciphertext, we only have to do three things in the vector: Delete the first position (index 0), whereby  all other positions are shifted to the front, insert 0 at the end, and  for the newly added letter search backwards for the first occurrence from the end and, if found, enter the distance there as a value:

```
S  H  C  O  E  N  S  Q  Q  V  T  Z  Z  O  I  Z ...
   0  0 10  0  0  0  1  0  0  0  1  3  0  0  0 
^                                   ^        ^

S  H  C  O  E  N  S  Q  Q  V  T  Z  Z  O  I  Z  N ...
      0 10  0 11  0  1  0  0  0  1  3  0  0  0  0 
   ^           ^                                ^
```

##### External representation of an isomorph pattern

The method `to_string()` converts the pattern into a `string`. For example, the pattern of the above examples `wqiqswazzrq` and `pasatpybbqa` will be output as

```
ABCBDAEFFGB
```

At the current development state, `to_string()` returns "`<pattern too complex>`" when more than 52 different letters (A-Z, a-z) would be needed to represent the pattern.

