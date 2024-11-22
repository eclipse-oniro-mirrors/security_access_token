/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ACCESSTOKEN_FUZZDATA_TEMPLATE_H
#define ACCESSTOKEN_FUZZDATA_TEMPLATE_H

#include <cstdio>
#include <string>

#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr uint32_t BOOL_MODULO_NUM = 2;
}
class AccessTokenFuzzData {
public:
    explicit AccessTokenFuzzData(const uint8_t *data, const size_t size)
        : data_(data), size_(size), pos_(0) {}

    template <class T> T GetData()
    {
        T object{};
        size_t objectSize = sizeof(object);
        if (data_ == nullptr || objectSize > size_ - pos_) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, data_ + pos_, objectSize);
        if (ret != EOK) {
            return {};
        }
        pos_ += objectSize;
        return object;
    }

    std::string GenerateStochasticString()
    {
        uint8_t strlen = GetData<uint8_t>();

        char cstr[strlen + 1];
        cstr[strlen] = '\0';

        for (uint8_t i = 0; i < strlen; i++) {
            char tmp = GetData<char>();
            if (tmp == '\0') {
                tmp = '1';
            }
            cstr[i] = tmp;
        }
        std::string str(cstr);
        return str;
    }

    template <class T> T GenerateStochasticEnmu(T enmuMax)
    {
        T enmuData = static_cast<T>(GetData<uint32_t>() % (static_cast<uint32_t>(enmuMax) + 1));
        return enmuData;
    }

    bool GenerateStochasticBool()
    {
        return (GetData<uint32_t>() % BOOL_MODULO_NUM) == 0;
    }

private:
    const uint8_t *data_;
    const size_t size_;
    size_t pos_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_FUZZDATA_TEMPLATE_H
