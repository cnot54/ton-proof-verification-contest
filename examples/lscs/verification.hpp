#pragma once

namespace tvm {
    namespace schema {

        // ===== Root Token Contract (Non-fungible) ===== //
        __interface iverificator {

            // expected offchain constructor execution
            __attribute__((internal, external, dyn_chain_parse)) void constructor(bytes proof_msg_bytes) = 11;

            __attribute__((getter)) bool_t verify() = 12;
        };

        struct dverificator {
            cell proof_msg_;
        };

        struct everificator { };
    }    // namespace schema
}    // namespace tvm
