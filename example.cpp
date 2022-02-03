#include "isomorph.hpp"

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

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

    auto res = cryptohelper::isomorphs::get_isomorphs<string>(ciphertext);
    for (auto p : res) {
        cout << "pattern " << p.first.to_string();
        cout << " (size = " << p.first.size();
        cout << ", significance = " << p.first.significance;
        cout << ") at " << p.second.size() << " positions:" << endl;
        for (auto i : p.second) {
            cout << setw(6) << i << ": " << 
                    ciphertext.substr(i, p.first.size()) << endl;
        }
        cout << endl;
    }
    return 0;
}