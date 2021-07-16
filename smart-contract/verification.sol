pragma ton-solidity >=0.30.0;
pragma AbiHeader pubkey;

contract Verify {

    bytes constant m_vkey = hex"e75b496b4475aa441545fcd6037aed168962c31a09295cc71adb01fd27482156a28265ec31dca269787fd73c842003036ca990991db5ef738a90b4e9a501997c8fd3581040ba4e7740073d8e25496686eea8ad3b5452102ee6e86b5ffb34dd06eec7e898e8c974657aff7b3d7f702c278310581511f7a2a7ba2926e3cfd1c3cadeb51b0f548bbeaa4235d9efd2aa59065aebd2198a3891a12d4f38d1e14493458eb738355aca11e9d84de44b951f43e62227691c45ae1e414f6576bbec856614edfeca169a514a8dd805c8094ceeaf2662bb220d483e3f534043dd8bba0a7da9e1be9965caaba5c6864f4a1a45a02615321c9c6f1aaf7a580c99c32bd1b9530ae8cc5fc0cf4f6e81f79f89581a6e110dae89570f029a56da6bce2117b9531402d2d6deff4a2b1ce700cbab3346579010835d3e37cace64773cdb4d0ecf138593ed5e428f39e3d07d0a5f229fd266230fa6c2da944503633ad2088c90c4df9ef92c926665b84ef21d6c7465274cdac2877538f116a5b47cee3ef9c6c5da67d607ff2d461a91cc84abbe1a90d68e1d9a4698d43797f3996dae3a25593008c580544eecd769c88598d357833f6839733617b15a75ace8c5b9fdde0bccadf7c0ec0031733746556f4bc3b38b8667db837e414e093e9822b6e99a7cf6aabf8dccee0bca700fd4478eff33e1e7527cc560a0ffc73bbb87f97008a621545c83784a8463208d50853bc807337eab5299734456121088c78527179b89676227867e58347e6177555d1c6d58ee274535ee681f411a79b90873304cac3a8209ba18b3e0580fb06775f0f0e2d05c862635ffc53bacd2297704855e39e9806ddc5a3bce27721899119180979470fe0289ea77d13131a61232d4850aeb8e7dffd8be96ef6c27401b6d90e80dc707aadfa75cdbffea0db4051b9c71a942657144c4fba9ae64bfd0abbd1b20e51e958e855107f1662a290ab0f31d7d67e22b51532380f51db5c82de437f164c9506701638a909c5d776cfc035ff8135c0c0158c06218c2940f07da3ac3ba84cf774aab155cdb581f8e15dab77ac74cd0c4697fa33558b6ca46c9beb03602dfb9b5f8010ff29c0829090d16c3952fbbffd99c55de41bb28efaaf913c575b099f15b731fb383490fcd52faaf020000000000000001000000b2db2804bcc0f9ab5e1e041e5fcb7f39dac78b8e3f91b33cc0c98c01cfa2c1cb76b2098f6ef4be01872c3a26cdb95fda9383698a73000727024c80b947ed433f152f028b4f43e8a009631ea8a714dfa4fbcb3ac1ee0642ee6aa44fa670234d6f0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    uint32 constant PRIMARY_INPUT_SIZE = 2;

    function verify(bytes proof,
                    uint32 min_salary,
                    uint32 min_age) public view returns (bool) {
        tvm.accept();
        string blob_str = proof;
        blob_str.append(serialize_primary_input(min_salary, min_age));
        blob_str.append(m_vkey);
        return tvm.vergrth16(blob_str);
    }

    function serialize_primary_input(uint32 min_salary, uint32 min_age) internal inline view returns(bytes) {
        string blob_str=(encode_little_endian(PRIMARY_INPUT_SIZE, 4));
        blob_str.append(encode_little_endian(uint256(min_salary), 32));
        blob_str.append(encode_little_endian(uint256(min_age), 32));
        return blob_str;
    }

    function encode_little_endian(uint256 number, uint32 bytes_size) internal pure returns (bytes){
        TvmBuilder ref_builder;
        for(uint32 i=0; i<bytes_size; ++i) {
            ref_builder.store(byte(uint8(number & 0xFF)));
            number>>=8;
        }
        TvmBuilder builder;
        builder.storeRef(ref_builder.toCell());
        return builder.toSlice().decode(bytes);
    }
}
