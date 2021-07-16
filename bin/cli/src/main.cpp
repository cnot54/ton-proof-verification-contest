#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include "detail/components.hpp"

typedef algebra::curves::bls12<381> curve_type;
typedef curve_type::scalar_field_type field_type;
typedef field_type::value_type value_type;
typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

using namespace nil::crypto3::zk::components;
using namespace nil::crypto3::zk::snark;

boost::filesystem::path PRIMARY_KEY_PATH = "prov_key",
    VERIFICATION_KEY_PATH = "ver_key",
    PROOF_PATH = "proof";

std::vector<std::uint8_t> readfile(boost::filesystem::path path) {
    boost::filesystem::ifstream stream(path, std::ios::in | std::ios::binary);
    auto eos = std::istreambuf_iterator<char>();
    auto buffer = std::vector<uint8_t>(std::istreambuf_iterator<char>(stream), eos);
    return buffer;
}

bool generate_keys() {
    blueprint<field_type> bp;
    contest::bank_component<field_type> contest_component(bp);
    contest_component.generate_r1cs_constraints();

    const r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    scheme_type::keypair_type keypair = generate<scheme_type>(constraint_system);

    std::vector<std::uint8_t> proving_key_byteblob =
        nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(keypair.first);
    std::vector<std::uint8_t> verification_key_byteblob =
        nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(keypair.second);

    boost::filesystem::ofstream pk_out(PRIMARY_KEY_PATH);
    for (const auto &v : proving_key_byteblob) {
        pk_out << v;
    }
    pk_out.close();
    std::cout << "prooving key saved to " << PRIMARY_KEY_PATH << std::endl;

    boost::filesystem::ofstream vk_out(VERIFICATION_KEY_PATH );
    for (const auto &v : verification_key_byteblob) {
        vk_out << v;
    }
    vk_out.close();
    std::cout << "verification key saved to " << VERIFICATION_KEY_PATH << std::endl;

    return true;
}


bool generate_proof(uint min_salary, uint min_age, uint salary, uint age) {
    std::vector<std::uint8_t> proving_key_byteblob = readfile(PRIMARY_KEY_PATH);
    nil::marshalling::status_type provingProcessingStatus = nil::marshalling::status_type::success;
    typename scheme_type::proving_key_type pk = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::proving_key_process(
        proving_key_byteblob.cbegin(),
        proving_key_byteblob.cend(),
        provingProcessingStatus);

    blueprint<field_type> bp;
    contest::bank_component<field_type> contest_component(bp);
    contest_component.generate_r1cs_constraints();
    contest_component.generate_r1cs_witness(min_salary, min_age, salary, age);

    std::cout << "Circuit satisfied: " << bp.is_satisfied() << std::endl;
    if (!bp.is_satisfied()) {
        return false;
    }

    const scheme_type::proof_type proof = prove<scheme_type>(pk, bp.primary_input(), bp.auxiliary_input());

    std::vector<std::uint8_t> proof_byteblob =
        nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(proof);

    std::cout << "proof is saved to " << PROOF_PATH << std::endl;
    boost::filesystem::ofstream proof_out(PROOF_PATH);
    for (const auto &v : proof_byteblob) {
        proof_out << v;
    }
    proof_out.close();

    return true;
}


bool verify_proof(uint min_salary, uint min_age) {
    std::vector<std::uint8_t> proof_byteblob = readfile(PROOF_PATH);
    nil::marshalling::status_type proofProcessingStatus = nil::marshalling::status_type::success;
    typename scheme_type::proof_type proof = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::proof_process(
        proof_byteblob.cbegin(),
        proof_byteblob.cend(),
        proofProcessingStatus);

    std::vector<std::uint8_t> verification_key_byteblob = readfile(VERIFICATION_KEY_PATH);
    nil::marshalling::status_type verificationProcessingStatus = nil::marshalling::status_type::success;
    typename scheme_type::verification_key_type vk = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::verification_key_process(
        verification_key_byteblob.cbegin(),
        verification_key_byteblob.cend(),
        verificationProcessingStatus );

    r1cs_primary_input<field_type> input = contest::get_public_input<field_type>(min_salary, min_age);
    using basic_proof_system = r1cs_gg_ppzksnark<curve_type>;
    const bool verified = verify<basic_proof_system>(vk, input, proof);
    std::cout << "proof verified " << verified << std::endl;

    return verified;
}


int main(int argc, char *argv[]) {
    uint salary, age;
    uint min_salary, min_age;

    boost::program_options::options_description options(
        "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
        "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator");
    options.add_options()
    ("help,h", "Display help message")
    ("keygen", "Generate keys")
    ("proof", "Generate proof")
    ("verify", "Verify proof")
    ("min-age,x", boost::program_options::value<uint>(&min_age)->default_value(18))
    ("min-salary,y", boost::program_options::value<uint>(&min_salary)->default_value(1000))
    ("age,a", boost::program_options::value<uint>(&age)->default_value(0))
    ("salary,s", boost::program_options::value<uint>(&salary)->default_value(0));

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    } else if (vm.count("keygen")) {
        generate_keys();
    } else if (vm.count("proof")) {
        generate_proof(min_salary, min_age, salary, age);
    } else if (vm.count("verify")) {
        verify_proof(min_salary, min_age);
    }
    return 0;
}
