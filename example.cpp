#include "isomorph.hpp"

#include <string>
#include <vector>
#include <iostream>

using namespace std;

int main() {
    // This ciphertext was the "Friedman Ring" challenge created by 
    // George Lasry in 2022, see
    // https://scienceblogs.de/klausis-krypto-kolumne/2022/01/29/die-friedman-ring-challenge-von-george-lasry/
    // Identifying the isomorphs was a crucial solving step

    string ciphertext =
        "shcoensqqvtzzoiznjczemkqr"
        "etrgwvnkjgjgsiskxshdrxzhm"
        "bradixassypnnqwkbazqrrmxi"
        "ibeizfkiacurjaxjpgzioqure"
        "quxarwohmjwdljbnpnkfqveir"
        "msigyomccnfbbglbouibyzeck"
        "yfkrqdetaaimjrgjkkkf";

    auto res = cryptohelper::get_isomorph_patterns<string>(ciphertext);
    for (auto p : res) {
        cout << "pattern " << p.first.to_string();
        cout << " (size = " << p.first.size();
        cout << ", significance = " << p.first.non_zero_count;
        cout << ") at " << p.second.size() << " positions:" << endl;
        for (auto i : p.second) {
            cout << i << ": " << ciphertext.substr(i, p.first.size()) << endl;
        }
        cout << endl;
    }
    return 0;
}