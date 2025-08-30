#pragma once

namespace simeng {

// TODO: This serialization scheme is not endianness-aware

#define serialize_field(BUFFER, FIELD)                                       \
  {                                                                          \
    static_assert(std::is_same_v<std::remove_cv_t<decltype(BUFFER)>,         \
                                 std::vector<uint8_t>&>,                     \
                  "`" #BUFFER                                                \
                  "` has to be a reference to a vector of uint8_t");         \
                                                                             \
    const auto* data_ptr = reinterpret_cast<const uint8_t*>(&FIELD);         \
    const span<uint8_t> data(const_cast<uint8_t*>(data_ptr), sizeof(FIELD)); \
    BUFFER.insert(BUFFER.cend(), data.cbegin(), data.cend());                \
  }

#define serialize_vector(BUFFER, FIELD)                                    \
  {                                                                        \
    static_assert(std::is_same_v<std::remove_cv_t<decltype(BUFFER)>,       \
                                 std::vector<uint8_t>&>,                   \
                  "`" #BUFFER                                              \
                  "` has to be a reference to a vector of uint8_t");       \
                                                                           \
    const auto len = FIELD.size();                                         \
    constexpr auto item_size = sizeof(decltype(FIELD)::value_type);        \
    const auto data_size = len * item_size;                                \
    BUFFER.reserve(sizeof(len) + data_size);                               \
                                                                           \
    serialize_field(BUFFER, len);                                          \
                                                                           \
    const auto* data_ptr = reinterpret_cast<const uint8_t*>(FIELD.data()); \
    const span<uint8_t> data(const_cast<uint8_t*>(data_ptr), data_size);   \
    BUFFER.insert(BUFFER.cend(), data.cbegin(), data.cend());              \
  }

#define serialize_regval_vector(BUFFER, FIELD)                              \
  {                                                                         \
    static_assert(std::is_same_v<std::remove_cv_t<decltype(BUFFER)>,        \
                                 std::vector<uint8_t>&>,                    \
                  "`" #BUFFER                                               \
                  "` has to be a reference to a vector of uint8_t");        \
    static_assert(                                                          \
        std::is_same_v<std::remove_cv_t<decltype(FIELD)::value_type>,       \
                       RegisterValue>,                                      \
        "`" #FIELD "` has to be a vector of RegisterValue");                \
                                                                            \
    const auto len = FIELD.size();                                          \
    serialize_field(BUFFER, len);                                           \
                                                                            \
    for (const auto& val : FIELD) {                                         \
      const auto val_len = val.size();                                      \
      serialize_field(BUFFER, val_len);                                     \
      if (val_len == 0) continue;                                           \
      const auto* data_ptr = val.getAsVector<uint8_t>();                    \
      const span<uint8_t> data(const_cast<uint8_t*>(data_ptr), val.size()); \
      BUFFER.insert(BUFFER.cend(), data.cbegin(), data.cend());             \
    }                                                                       \
  }

#define deserialize_field(BYTES, FIELD)                                     \
  {                                                                         \
    static_assert(                                                          \
        std::is_same_v<std::remove_cv_t<decltype(BYTES)>, span<uint8_t>&>,  \
        "`" #BYTES "` has to be a reference to a span of uint8_t");         \
                                                                            \
    auto* ptr = const_cast<decltype(FIELD)*>(&FIELD);                       \
    std::memcpy(reinterpret_cast<void*>(ptr), BYTES.data(), sizeof(FIELD)); \
    BYTES = {BYTES.data() + sizeof(FIELD), BYTES.size() - sizeof(FIELD)};   \
  }

#define deserialize_vector(BYTES, FIELD)                                      \
  {                                                                           \
    using value_type = decltype(FIELD)::value_type;                           \
    using size_type = decltype(FIELD)::size_type;                             \
    static_assert(                                                            \
        std::is_same_v<std::remove_cv_t<decltype(BYTES)>, span<uint8_t>&>,    \
        "`" #BYTES "` has to be a reference to a span of uint8_t");           \
                                                                              \
    assert(FIELD.empty() && "Cannot deserialize into a non-empty vector");    \
                                                                              \
    size_type len = 0;                                                        \
    deserialize_field(BYTES, len);                                            \
                                                                              \
    const auto* data_ptr = reinterpret_cast<const value_type*>(BYTES.data()); \
    const span data_span = {const_cast<value_type*>(data_ptr), len};          \
    FIELD.insert(FIELD.cend(), data_span.cbegin(), data_span.cend());         \
                                                                              \
    const auto size = len * sizeof(value_type);                               \
    BYTES = {BYTES.data() + size, BYTES.size() - size};                       \
  }

#define deserialize_regval_vector(BYTES, FIELD)                                \
  {                                                                            \
    using value_type = decltype(FIELD)::value_type;                            \
    using size_type = decltype(FIELD)::size_type;                              \
    static_assert(                                                             \
        std::is_same_v<std::remove_cv_t<decltype(BYTES)>, span<uint8_t>&>,     \
        "`" #BYTES "` has to be a reference to a span of uint8_t");            \
    static_assert(std::is_same_v<std::remove_cv_t<value_type>, RegisterValue>, \
                  "`" #FIELD "` has to be a vector of RegisterValue");         \
                                                                               \
    size_type len = 0;                                                         \
    deserialize_field(BYTES, len);                                             \
                                                                               \
    FIELD.reserve(len);                                                        \
    for (size_type i = 0; i < len; i++) {                                      \
      using len_t =                                                            \
          std::invoke_result_t<decltype(&RegisterValue::size), RegisterValue>; \
                                                                               \
      len_t val_len = 0;                                                       \
      deserialize_field(BYTES, val_len);                                       \
      if (val_len == 0) {                                                      \
        FIELD.emplace_back();                                                  \
        continue;                                                              \
      }                                                                        \
      assert(val_len <= static_cast<len_t>(static_cast<uint16_t>(-1)) &&       \
             "RegisterValue length overflow");                                 \
                                                                               \
      const auto* data_ptr = reinterpret_cast<const char*>(BYTES.data());      \
      FIELD.emplace_back(data_ptr, static_cast<uint16_t>(val_len));            \
                                                                               \
      BYTES = {BYTES.data() + val_len, BYTES.size() - val_len};                \
    }                                                                          \
  }

}  // namespace simeng
