#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/comparison.hpp>
#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/sha256_component.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

using namespace nil::crypto3::zk::components;
using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

namespace contest {

    template<typename FieldT>
    class bank_component : public component<FieldT> {

        public:
            blueprint_variable<FieldT> out;

            blueprint_variable<FieldT> salary, salaryReference;
            blueprint_variable<FieldT> salaryCmpLess, salaryCmpLessOrEq;

            blueprint_variable<FieldT> age, ageReference;
            blueprint_variable<FieldT> ageCmpLess, ageCmpLessOrEq;

            std::shared_ptr<comparison<FieldT>> salaryCmp, ageCmp;

        bank_component(blueprint<FieldT> &bp) : component<FieldT>(bp) {
            salaryReference.allocate(this->bp);
            ageReference.allocate(this->bp);

            out.allocate(this->bp);

            salary.allocate(this->bp);
            age.allocate(this->bp);

            salaryCmpLess.allocate(this->bp);
            salaryCmpLessOrEq.allocate(this->bp);
            ageCmpLess.allocate(this->bp);
            ageCmpLessOrEq.allocate(this->bp);

            this->bp.set_input_sizes(2);
        }
        /**
         * generate R1 Constraint System for the component
         */
        void generate_r1cs_constraints() {
            size_t cmp_size = 20;

            salaryCmp.reset(new comparison<FieldT>(this->bp,
                cmp_size,
                salaryReference,
                salary,
                salaryCmpLess,
                salaryCmpLessOrEq));
            salaryCmp.get()->generate_r1cs_constraints();

            ageCmp.reset(new comparison<FieldT>(this->bp,
                cmp_size,
                ageReference,
                age,
                ageCmpLess,
                ageCmpLessOrEq));
            ageCmp.get()->generate_r1cs_constraints();

            // age > ageReference && salary > salaryReference == true
            this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(salaryCmpLessOrEq + ageCmpLessOrEq, 1, out));
        }

        /**
         * generate witnesses for the constraint system of this component
         * need to provide assignment to necessary variables
         */
        void generate_r1cs_witness(uint min_salary, uint min_age, uint salary_input, uint age_input) {
            this->bp.val(salaryReference) = min_salary;
            this->bp.val(ageReference) = min_age;

            this->bp.val(salary) = salary_input;
            this->bp.val(age) = age_input;

            salaryCmp.get()->generate_r1cs_witness();
            ageCmp.get()->generate_r1cs_witness();

            this->bp.val(out) = 2;
        }
    };

    template<typename FieldT>
    r1cs_primary_input<FieldT> get_public_input(uint min_salary, uint min_age) {
        r1cs_primary_input<FieldT> input;
        input.push_back(min_salary);
        input.push_back(min_age);
        return input;
    }
}
