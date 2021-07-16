pragma ton-solidity >=0.30.0;
pragma AbiHeader pubkey;

contract Verify {

    bytes constant m_vkey = hex"9b85df0a1c00c228692c51747b5429b436123baa9caaacc2798642ce4f80dd56bb39a3fdf3117b02b87558f35486d01940565adfa5f236c6de89a0282f0e9f459f761f09eb6cd469a23f295db9544c36f35ebd7b5f2765657cb5f307888475048a8122947db221272cfc5abb6d56110cf0b4f3c6169c3ecec839540e77e1403109357582441de3d03b1467e716c3f002a0946fd303279c0c8999011f4c473d5bec934d3caf0a756c958949209a1c4c0e03ea33ce967273430eb1cf2fd30d8a0c324015393377a3d1463c73f922c153ae071e251d645c4a3fe710ff5d656985bf90feaea2a4a49c0ccbe18d0d0f47c915c92474f066eb89eb8cdbdf6bbc6ca2407b54bed331b37faa597cbe18a23cda795ee8c496de613b1097a27cb4c81b5607d50871a81ca6618bc06169e93de390927e79faf858e3fb9db07f95f234d9b9466cc7270cb046d564e93814f94fcf470585dfefba72fb0e823b9afb843e6a346ccdd8bdd9620dd350170294a7644f6948b539ff1ee8dbe9273c0da6aa5b2dc915a7ea6e5b4416ecdffc004d979931219d767734e74b89818c6b5100593a03d80287b421208d7e8eacf52d1fb7eb78a3128e60e5fdf3d273f819827fc044df254dd147d6e5c8b5622ae40389fbfb91d860c86bc5c2f717bd0daeab0be8e43ca21361e1e0e010322ba63cad851d2ed9e4dbb7e969185e8d673c8ec1d037e1f1a53c040bc0b27e70478e6b35de5a0f072d186aeee6090ce71f35e59bbd808975a1826db37eb60ce0f9a0f7348fa5a4ce548752df245c928684fdeffe87c37a4a7311a82d2b741561e4907b8b6e6f01989f585af6ce3f52386951e424b27dc7ae54b15a1a72b373c2b240fc188111d5185be01971fee74d573864dd314cf32ed930cfb42eb336c2fc1c12d8087fe5a58867d2c1cc152a1b5c774d5b0622d2fc61718f85c8dde1106c631227425b02c9aab65a1c76360a0854ab0af90bc034f7cff68378ce3eb9788f0986758def018d8f66b90e32e3cb92e48240eebc2a20b5cbe3cfd7f7e7bdce627ce91121e68ec61db2df62820fcd85e9b5d026d7028ae3443e87b8d4dd80ddc2ee0072358f34a58888bd9cc5cc9918cf163bd0f3df3009e8a4e898fbfca1977c8cd2f35f25b98e8ddcb6020000000000000001000000ade435ff5364e9bfa83bb16340c6ccf9985b66297eb3371e25eb72c2fe0cd71374a833c8403d5a4f87e98dae949c088eb1146eeb0cae27ee1e5abfe143c81bc1bbb4acdc4a4b990377b2b5d9101356b9a198fe9f2ede4db274cb30d9c3185a710200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    uint32 constant PI_SIZE = 2; //change that
    uint8 constant field_element_bytes = 32;

    // You should change/add/remove arguments according to your circuit.
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
        string blob_str=(encode_little_endian(PI_SIZE, 4));
        blob_str.append(encode_little_endian(uint256(min_salary), field_element_bytes));
        blob_str.append(encode_little_endian(uint256(min_age), field_element_bytes));
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
