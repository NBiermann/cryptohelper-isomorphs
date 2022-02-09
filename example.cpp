#include "isomorph.hpp"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int main() {
    string plaintext =
        "ribonucleic_acid_strands_are_created_using_deoxyri"
        "bonucleic_acid_strands_as_a_template_in_a_procesq_"
        "calqed_transcription_where_deoxyribonucleic_acid_b"
        "ases_are_exchanged_for_their_corqesponding_bases_e"
        "xcept_in_the_case_of_thymine_for_which_ribonucleic"
        "_acid_substitutes_uracil_under_the_genetic_code_th"
        "ese_ribonucleic_acid_strands_specify_the_sequence_"
        "of_amino_acids_within_proteins_in_a_procesq_calqed"
        "_translation";

    // the used Wheatstone key is:
    // plain ring : _abcdefghijklmnopqrstuvwxyz / start pos.5(e)
    // cipher ring: otzvfxmbliajcqwnskheypgurd  / start pos.2(z)
    // http://www.jproc.ca/crypto/wheatstone.html
    // https://incoherency.co.uk/blog/stories/wheatstone-cryptograph.html
    // https://scienceblogs.de/klausis-krypto-kolumne/2022/01/29/die-friedman-ring-challenge-von-george-lasry/

    string ciphertext =
        "nbtwwpfqbjmfxbqimdodigqzajzscnfhnlyykcjzbtpdoaeywm"
        "oqqyvcmaxvfmclxrdrlpctiazajjxkdzdnlysdfkhhlaludqcg"
        "driwvvoyevspmpqyrwyybfswtnjnsoiafgsvvaezgopeygzrpu"
        "unzsrdsfoxrfivsaiimcprbtswhtaqdzzkxvvvydfrhyycdqpo"
        "edtcsumjrhbxtfvplfejmonmphunjkovcipgkgnbdemmqgxdvr"
        "gudxtrketheiyppbpvrgmlwkmtpcqoivhscehtelrekymgueqz"
        "owtunbtwwpfqbjmfxbqimdodigqzavtksgyqnirghjrawdlrog"
        "jvrdjlqwotvixyzdcucqhxpupocspolkgiaaozonkxfwkstmpp"
        "hcjplqbusmcc";

    cout << "The following text ..."
         << endl
         << endl
         << plaintext << endl
         << endl
         << "... was encrypted using a Wheatstone disk to the following "
            "ciphertext:" << endl << endl
         << ciphertext << endl << endl
         << "Now, let's see how the many repeated text segments lead "
            "to isomorphs in the\n"
         << "ciphertext (only patterns with a significance greater or "
            "equal to 2 are shown):"
         << endl << endl;

    auto res = cryptohelper::isomorphs::get_isomorphs<string>(ciphertext);
    for (auto p : res) {
        cout << "pattern " << p.first.to_string();
        cout << " (size = " << p.first.size();
        cout << ", significance = " << p.first.significance;
        cout << ") at " << p.second.size() << " positions:" << endl;
        for (auto i : p.second) {
            cout << setw(6) << i << ": " << 
                ciphertext.substr(i, p.first.size())
                 << " | " << plaintext.substr(i, p.first.size()) << endl;
        }
        cout << endl;
    }

    cout << "One may use this information to reduce the number of possible \n"
            "ciphertext alphabets to 12 (if we consider alphabets as equal \n"
            "which can be transformed into each other by rotation). This \n"
            "task is left up to you :-)\n" 
         << endl 
         << "As can be seen here well, a significance of 2 does not reliably\n"
            "indicate that the corresponding plaintext passages are identical.\n"
            "Better use only the isomorphs with higher significance - their \n"
            "validity is much higher (although not exactly at 100%)."
         << endl << endl;
    return 0;
}