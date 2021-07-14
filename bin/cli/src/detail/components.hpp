#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/comparison.hpp>
#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/hashes/hash_io.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/sha256_construction.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/sha256_component.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include "pack_vector.hpp"


using namespace nil::crypto3::zk::components;
using namespace nil::crypto3::zk::snark;

template<typename FieldType>
class factorial_component : public component<FieldType> {
private:
    blueprint_variable_vector<FieldType> S;

public:
    const std::size_t n;
    const blueprint_variable<FieldType> result;

    factorial_component(blueprint<FieldType> &bp, std::size_t n, const blueprint_variable<FieldType> &result) : component<FieldType>(bp), n(n), result(result) {
        S.allocate(bp, n - 1);
    }

    // 3! = 1 * 2 * 3
    // 1 * 1 = n1
    // 2 * n1 = n2
    // 3 * n2 = result

    void generate_r1cs_constraints() {
        for (std::size_t i = 0; i < n; ++i) {
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>(
                i + 1, i == 0 ? 1 : S[i - 1], i == n - 1 ? result : S[i]
            ));
        }
    }

    void generate_r1cs_witness() {
        typename FieldType::value_type total = FieldType::value_type::one();
        for (std::size_t i = 0; i < n; ++i) {
            total *= (i + 1);
            this->bp.val(i == n - 1 ? result : S[i]) = total;
            std::cout << "i(" << i << ") = " << this->bp.val(i == n - 1 ? result : S[i]).data << std::endl;
        }
    }
};


template<typename FieldType>
class pow_component : public component<FieldType> {
private:
    blueprint_variable_vector<FieldType> S;

public:
    const std::size_t n;
    const blueprint_variable<FieldType> X;
    const blueprint_variable<FieldType> result;

    pow_component(blueprint<FieldType> &bp,
        const blueprint_variable<FieldType> &X,
        std::size_t n,
        const blueprint_variable<FieldType> &result) :
    component<FieldType>(bp),
        X(X), n(n), result(result) {
        // assert(X.size() > 0);
        S.allocate(bp, n - 1);
    }

    void generate_r1cs_constraints() {
        for (std::size_t i = 0; i <= n; ++i) {
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>(
                X, i == 0 ? X : S[i - 1], i == n - 1 ? result : S[i]
            ));
        }
        // 0: 1 * 1 = S[0]
        // 1: X * 1 = S[1]
        // 2: X * S[1] = S[2]

        // 0: X * X = S[0]
        // 1: X * S[0] = S[i]
        // 2: X * S[1] = result
    }

    void generate_r1cs_witness() {
        // X.evaluate(this->bp);

        typename FieldType::value_type total = this->bp.val(X);

        for (std::size_t i = 0; i < n; ++i) {
            if (i == n -1) {
                this->bp.val(result) = this->bp.val(S[i - 1]);
                std::cout << "result = " << this->bp.val(result).data << std::endl;
            } else {
                this->bp.val(S[i]) = this->bp.val(X) * total;
                std::cout << "i(" << i << ") = " << this->bp.val(S[i]).data << std::endl;
            }
            total = this->bp.val(X) * total;

            // 0: S[0] = X * X
            // 1: S[i] = X *
            // 2: X * S[1] = result
        }
    }
};


const size_t sha256_digest_len = 256;


/*
   computed by:
   unsigned long long bitlen = 256;
   unsigned char padding[32] = {0x80, 0x00, 0x00, 0x00, // 24 bytes of padding
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32, // message length
   bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
   };
   std::vector<bool> padding_bv(256);
   convertBytesToVector(padding, padding_bv);
   printVector(padding_bv);
   */

/* this is needed as a 2-to-1-compression sha256-gadget is used, thus we pad our input to 512 */
bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};


bool debug = false;

uint64_t extractFromBV(const std::vector<bool> &r, uint8_t slot_offset) {
    uint64_t var = 0;

    if (slot_offset > 2) {
        printf("current construction only allows 3 elements in a zklaim payload!\n");
        printf("returning -1 dummy value");
        return -1;
    }

    // recovering age from bitvector
    for (size_t i = 0; i < 8; i++) {
        for (size_t k=0; k < 8; k++) {
            if (debug)
                printf("%d ", r[slot_offset*64+i*8+k]);
            var |= (uint64_t) r[slot_offset*64+i*8+k] << (8-1+i*8-k);
        }
    }
    if (debug) {
        printf("\n");

        for (size_t i = 0; i < 8; i++) {
            uint8_t tmp = ((uint64_t) var >> i*8) & 0xff;
            for (size_t k=0; k < 8; k++) {
                printf("%lu ", (tmp >> k) & (1ul));
            }
        }
    }

    return var;
}

using namespace nil::crypto3::algebra;
using namespace std;

template<typename FieldT>
class l_component : public component<FieldT> {
    public:
        blueprint_variable_vector<FieldT> input_as_field_elements; /* R1CS input */
        blueprint_variable_vector<FieldT> input_as_bits; /* unpacked R1CS input */
        blueprint_variable_vector<FieldT> plvars;
        blueprint_variable_vector<FieldT> PL;

        shared_ptr<multipacking_component<FieldT> > unpack_inputs; /* multipacking gadget */

        shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
        shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */

        shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding */
        shared_ptr<sha256_compression_function_component<FieldT>> h_r1; /* hashing gadget for r1 */
        shared_ptr<multipacking_component<FieldT> > pack_PL;

        /* variables that will be used for the comparison */
        /* note, that the last two will be implicitely assigned*/
        blueprint_variable<FieldT> age, age_reference, age_less, age_less_or_eq,
            salary, salary_reference, salary_less, salary_less_or_eq;
        shared_ptr<comparison<FieldT>> age_cg, salary_cg;

        /* field's "zero", for reference */
        blueprint_variable<FieldT> zero;
        blueprint_variable_vector<FieldT> padding_var; /* SHA256 length padding */


        l_component(blueprint<FieldT> &bp) : component<FieldT>(bp, "l_component")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * 1;

        // we use a "multipacking" technique which allows us to constrain
        // the input bits in as few field elements as possible.
        const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
        input_as_field_elements.allocate(bp, input_size_in_field_elements, "input_as_field_elements");
        this->bp.set_input_sizes(input_size_in_field_elements);

        zero.allocate(this->bp, FMT(this->annotation_prefix, "zero"));

        /*
         * ALLOCATION AND INITIALIZATION OF COMPARISON GADGET
         */
        const size_t comp_b = 64;
        age_reference.allocate(this->bp, "reference value to compare for");
        this->bp.val(age_reference) = FieldT(18);
        age.allocate(this->bp, "value from payload");

        age_less.allocate(this->bp, "less");
        age_less_or_eq.allocate(this->bp, "less_or_eq");

        salary_less.allocate(this->bp, "less");
        salary_less_or_eq.allocate(this->bp, "less_or_eq");

        salary_reference.allocate(this->bp, "reference value to compare for");
        this->bp.val(salary_reference) = FieldT(50000);
        salary.allocate(this->bp, "value from payload");


        plvars.allocate(this->bp, 4, "input validation");

        // allocate and init comparison gadget
        age_cg.reset(new comparison<FieldT>(this->bp,
                    comp_b,
                    age_reference,
                    age,
                    age_less,
                    age_less_or_eq,
                    FMT(this->annotation_prefix, "comparison component")));

        salary_cg.reset(new comparison<FieldT>(this->bp,
                    comp_b,
                    salary_reference,
                    salary,
                    salary_less,
                    salary_less_or_eq,
                    FMT(this->annotation_prefix, "comparison component")));

        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(FieldT::value_type::one());
            else
                padding_var.emplace_back(FieldT::value_type::zero());
        }

        // verifier (and prover) inputs:
        h1_var.reset(new digest_variable<FieldT>(this->bp, sha256_digest_len, "h1"));

        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());

        // multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_component<FieldT>(this->bp,
                    input_as_bits,
                    input_as_field_elements,
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " unpack_inputs")));

        // prover inputs:
        r1_var.reset(new digest_variable<FieldT>(this->bp, sha256_digest_len, "r1"));

        for (int i = 0; i<32; i++) {
            for (int k=7; k>=0; k--) {
                PL.insert(PL.end(), r1_var->bits.begin()+k+i*8, r1_var->bits.begin()+k+1+i*8);
            }
        }

        //PL.insert(PL.end(), r1_var->bits.begin()+8, r1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), r1_var->bits.begin(), r1_var->bits.end());
        // IV for SHA256
        blueprint_variable_vector<FieldT> IV = SHA256_default_IV(bp);

        pack_PL.reset(new multipacking_component<FieldT>(bp, PL, plvars, 64, FMT(this->annotation_prefix, " pack_alpha")));

        // initialize the block component for r1's hash
        h_r1_block.reset(new block_variable<FieldT>(this->bp, {
                    r1_var->bits,
                    padding_var
                    }, "h_r1_block"));

        // initialize the hash component for r1's hash
        h_r1.reset(new sha256_compression_function_component<FieldT>(this->bp,
                    IV,
                    h_r1_block->bits,
                    *h1_var,
                    "h_r1"));

    }
        /**
         * generate R1 Constraint System for the component
         */
        void generate_r1cs_constraints()
        {
            // Multipacking constraints (for input validation)
            unpack_inputs->generate_r1cs_constraints(true);

            // Ensure bitness of the digests. Bitness of the inputs
            // is established by `unpack_inputs->generate_r1cs_constraints(true)`
            r1_var->generate_r1cs_constraints();

            // sanity check
            generate_r1cs_equals_const_constraint<FieldT>(this->bp, zero, FieldT::zero(), "zero");

            // activates the comparison component
            // this is needed such that less and less_or_eq are set
            age_cg.get()->generate_r1cs_constraints();

            salary_cg.get()->generate_r1cs_constraints();

            // enforce the reference value not be changable by the prover
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age_reference-18, 0));
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(1, salary_reference-50000, 0));

            // enforce that what we compare is also contained in the input at the
            // right slot
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age - plvars[0], 0));
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(1, salary - plvars[1], 0));

            // value should be less!
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age_less_or_eq, 1));
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(1, salary_less, 1));

            // constraint to ensure the hashes validate.
            h_r1->generate_r1cs_constraints();
        }

        /**
         * generate witnesses for the constraint system of this component
         * need to provide assignment to necessary variables
         */
        void generate_r1cs_witness(const std::vector<bool> &h1, const std::vector<bool> &r1)
        {
            // fill pre-image with witnessed data
            r1_var->bits.fill_with_bits(this->bp, r1);

            // dirty hack: copy bitvector back to mem region
            uint64_t cred_age = extractFromBV(r1, 0),
                     cred_salary = extractFromBV(r1, 1);
            //cout << endl << typeid(r1_var.get()->bits.get_bits(this->bp)[0]).name() << endl;
            //cout << cred->get_bits();

            //cout << endl << cred_salary << endl << endl;
            //_exit(1);
            // Set the zero blueprint_variable to zero
            this->bp.val(zero) = FieldT::zero();
            // prover sets the age contained in her credential
            // this is enforced by the circuit
            this->bp.val(age) = FieldT(cred_age);
            this->bp.val(salary) = FieldT(cred_salary);
            this->bp.val(salary_reference) = FieldT(50000);
            this->bp.val(age_reference) = FieldT(18);

            age_cg.get()->generate_r1cs_witness();
            salary_cg.get()->generate_r1cs_witness();

            //printf("less: %d\n", this->bp.val(less).as_ulong());

            // generate witness for other components in use (hash component, etc.)
            h_r1->generate_r1cs_witness();
            unpack_inputs->generate_r1cs_witness_from_bits();

            pack_PL->generate_r1cs_witness_from_bits();
            h1_var->bits.fill_with_bits(this->bp, h1);
            cout << endl << plvars.get_vals(this->bp) << endl;
            cout << input_as_field_elements.get_vals(this->bp) << endl;
        }
};


// /**
//  *  this is needed as to map the verifiers input to a single primary input for the verification algorithm
//  *  this also has to be adapted for possibly changed inputs the verifier might have
//  */
// template<typename FieldT>
// r1cs_primary_input<FieldT> l_input_map(const std::vector<bool> &h1)
// {
//     // construct the multipacked field points which encode
//     // the verifier's knowledge. This is the "dual" of the
//     // multipacking gadget logic in the constructor.
//     // TODO: get rid of assert as it is not working anyway
//     assert(h1.size() == sha256_digest_len);

//     std::vector<bool> input_as_bits;
//     input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());

//     vector<FieldT> input_as_field_elements = algebra::pack_std::vector<bool>_into_field_element_vector<FieldT>(input_as_bits);
//     return input_as_field_elements;
// }



template<typename FieldT>
class l_gadget : public component<FieldT> {
public:
    blueprint_variable_vector<FieldT> input_as_field_elements; /* R1CS input */
    blueprint_variable_vector<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_component<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
    std::shared_ptr<digest_variable<FieldT>> h2_var; /* H(R2) */

    std::shared_ptr<digest_variable<FieldT>> x_var; /* X */
    std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */
    std::shared_ptr<digest_variable<FieldT>> r2_var; /* R2 */

    std::shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding */
    std::shared_ptr<sha256_compression_function_component<FieldT>> h_r1; /* hashing gadget for r1 */

    std::shared_ptr<block_variable<FieldT>> h_r2_block; /* 512 bit block that contains r2 + padding */
    std::shared_ptr<sha256_compression_function_component<FieldT>> h_r2; /* hashing gadget for r2 */

    blueprint_variable<FieldT> zero;
    blueprint_variable_vector<FieldT> padding_var; /* SHA256 length padding */


    l_gadget(blueprint<FieldT> &bp) : component<FieldT>(bp, "l_gadget")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * 3;
        {
            // We use a "multipacking" technique which allows us to constrain
            // the input bits in as few field elements as possible.
            const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
            input_as_field_elements.allocate(bp, input_size_in_field_elements, "input_as_field_elements");
            this->bp.set_input_sizes(input_size_in_field_elements);
        }

        zero.allocate(this->bp, FMT(this->annotation_prefix, "zero"));

        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(FieldT::one());
            else
                padding_var.emplace_back(FieldT::zero());
        }

        // Verifier (and prover) inputs:
        h1_var.reset(new digest_variable<FieldT>(bp, sha256_digest_len, "h1"));
        h2_var.reset(new digest_variable<FieldT>(bp, sha256_digest_len, "h2"));
        x_var.reset(new digest_variable<FieldT>(bp, sha256_digest_len, "x"));

        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h2_var->bits.begin(), h2_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), x_var->bits.begin(), x_var->bits.end());

        // Multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_component<FieldT>(this->bp, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
        r1_var.reset(new digest_variable<FieldT>(bp, sha256_digest_len, "r1"));
        r2_var.reset(new digest_variable<FieldT>(bp, sha256_digest_len, "r2"));

        // IV for SHA256
        blueprint_variable_vector<FieldT> IV = SHA256_default_IV(bp);

        // Initialize the block gadget for r1's hash
        h_r1_block.reset(new block_variable<FieldT>(bp, {
            r1_var->bits,
            padding_var
        }, "h_r1_block"));

        // Initialize the hash gadget for r1's hash
        h_r1.reset(new sha256_compression_function_component<FieldT>(bp,
                                                                  IV,
                                                                  h_r1_block->bits,
                                                                  *h1_var,
                                                                  "h_r1"));

        // Initialize the block gadget for r2's hash
        h_r2_block.reset(new block_variable<FieldT>(bp, {
            r2_var->bits,
            padding_var
        }, "h_r2_block"));

        // Initialize the hash gadget for r2's hash
        h_r2.reset(new sha256_compression_function_component<FieldT>(bp,
                                                                  IV,
                                                                  h_r2_block->bits,
                                                                  *h2_var,
                                                                  "h_r2"));
    }
    void generate_r1cs_constraints()
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r1_var->generate_r1cs_constraints();
        r2_var->generate_r1cs_constraints();

        generate_r1cs_equals_const_constraint<FieldT>(this->bp, zero, FieldT::zero(), "zero");

        for (unsigned int i = 0; i < sha256_digest_len; i++) {
            // This is the constraint that R1 = R2 ^ X.
            // (2*b)*c = b+c - a
            this->bp.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { r2_var->bits[i] * 2 }, // 2*b
                    { x_var->bits[i] }, // c
                    { r2_var->bits[i], x_var->bits[i], r1_var->bits[i] * (-1) }), // b+c - a
                FMT(this->annotation_prefix, " xor_%zu", i));
        }

        // These are the constraints to ensure the hashes validate.
        h_r1->generate_r1cs_constraints();
        h_r2->generate_r1cs_constraints();
    }
    void generate_r1cs_witness(const std::vector<bool> &h1,
                               const std::vector<bool> &h2,
                               const std::vector<bool> &x,
                               const std::vector<bool> &r1,
                               const std::vector<bool> &r2
                              )
    {
        // Fill our digests with our witnessed data
        x_var->bits.fill_with_bits(this->bp, x);
        r1_var->bits.fill_with_bits(this->bp, r1);
        r2_var->bits.fill_with_bits(this->bp, r2);

        // Set the zero blueprint_variable to zero
        this->bp.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r1->generate_r1cs_witness();
        h_r2->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h1_var->bits.fill_with_bits(this->bp, h1);
        h2_var->bits.fill_with_bits(this->bp, h2);
    }
};





template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const std::vector<bool> &h1,
                                             const std::vector<bool> &h2,
                                             const std::vector<bool> &x
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(h1.size() == sha256_digest_len);
    assert(h2.size() == sha256_digest_len);
    assert(x.size() == sha256_digest_len);

    std::vector<bool> input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());
    input_as_bits.insert(input_as_bits.end(), h2.begin(), h2.end());
    input_as_bits.insert(input_as_bits.end(), x.begin(), x.end());
    std::vector<FieldT> input_as_field_elements;// = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}
