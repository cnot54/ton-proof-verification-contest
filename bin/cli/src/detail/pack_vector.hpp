int64_t div_ceil(int64_t x, int64_t y)
{
    return (x + (y-1)) / y;
}

template<typename FieldT>
std::vector<FieldT> pack_bit_vector_into_field_element_vector(const std::vector<bool> &v, const size_t chunk_bits)
{
    assert(chunk_bits <= FieldT::capacity());

    const size_t repacked_size = div_ceil(v.size(), chunk_bits);
    std::vector<FieldT> result(repacked_size);

    for (size_t i = 0; i < repacked_size; ++i)
    {
        bigint<FieldT::num_limbs> b;
        for (size_t j = 0; j < chunk_bits; ++j)
        {
            b.data[j / GMP_NUMB_BITS] |= ((i * chunk_bits + j) < v.size() && v[i * chunk_bits + j] ? 1ll : 0ll) << (j % GMP_NUMB_BITS);
        }
        result[i] = FieldT(b);
    }

    return result;
}

template<typename FieldT>
std::vector<FieldT> pack_bit_vector_into_field_element_vector(const std::vector<bool> &v)
{
    return pack_bit_vector_into_field_element_vector<FieldT>(v, FieldT::capacity());
}
