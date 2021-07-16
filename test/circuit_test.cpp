#define BOOST_TEST_MODULE circuit_test
#include <boost/test/included/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

typedef algebra::curves::bls12<381> curve_type;
typedef curve_type::scalar_field_type field_type;
typedef field_type::value_type value_type;
typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

#include "../bin/cli/src/detail/components.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;


template<typename FieldType>
bool is_satisfied(uint min_salary, uint min_age, uint salary, uint age) {
    blueprint<field_type> bp;
    contest::bank_component<field_type> contest_component(bp);
    contest_component.generate_r1cs_constraints();
    contest_component.generate_r1cs_witness(min_salary, min_age, salary, age);
    return bp.is_satisfied();
}

BOOST_AUTO_TEST_SUITE(test_suite)

BOOST_AUTO_TEST_CASE(test_bank_component) {
    uint min_salary = 1000, min_age = 18;
    uint low_salary = 800, low_age = 16;
    uint big_salary = 1500, big_age = 21;

    std::cout << "Starting tests..." << std::endl;

    std::cout << "Testing valid inputs..." << std::endl;
    BOOST_CHECK(is_satisfied<field_type>(min_salary, min_age, min_salary, min_age) == true);
    BOOST_CHECK(is_satisfied<field_type>(min_salary, min_age, big_salary, big_age) == true);

    std::cout << "Testing invalid inputs..." << std::endl;
    BOOST_CHECK(is_satisfied<field_type>(min_salary, min_age, low_salary, big_age) == false);
    BOOST_CHECK(is_satisfied<field_type>(min_salary, min_age, low_salary, min_age) == false);
    BOOST_CHECK(is_satisfied<field_type>(min_salary, min_age, big_salary, low_age) == false);
    BOOST_CHECK(is_satisfied<field_type>(min_salary, min_age, min_salary, low_age) == false);
    BOOST_CHECK(is_satisfied<field_type>(min_salary, min_age, low_salary, low_age) == false);

    std::cout << "Tests completed!" << std::endl;
}
BOOST_AUTO_TEST_SUITE_END()
