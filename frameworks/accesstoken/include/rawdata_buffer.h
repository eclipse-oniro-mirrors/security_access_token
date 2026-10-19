/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_RAWDATA_BUFFER_H
#define ACCESSTOKEN_RAWDATA_BUFFER_H

#include <cstdint>
#include <cstdlib>
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_BUNDLE_INFOS_RAW_DATA_SIZE = 128 * 1024 * 1024;  // 128MB
constexpr uint32_t MAX_BUNDLE_INFO_SIZE = 128;
}

/**
 * @brief Common raw buffer holder for idl rawdata types.
 * Each idl rawdata type maps to a distinct C++ class name, so concrete
 * rawdata classes stay as empty shells inheriting this base.
 */
class RawdataBuffer {
public:
    uint32_t size = 0;
    const void* data = nullptr;

    // the destructor frees the owned buffer, so a shallow copy would double
    // free it; copying is forbidden until a deep copy/move is actually needed
    RawdataBuffer() = default;
    RawdataBuffer(const RawdataBuffer&) = delete;
    RawdataBuffer& operator=(const RawdataBuffer&) = delete;

    ~RawdataBuffer()
    {
        if (data != nullptr) {
            free(const_cast<void*>(data));
            data = nullptr;
        }
    }

    int32_t RawDataCpy(const void* readData)
    {
        if ((readData == nullptr) || (size == 0) || (size >= MAX_BUNDLE_INFOS_RAW_DATA_SIZE)) {
            return -1;
        }
        void* buffer = malloc(size);
        if (buffer == nullptr) {
            return -1;
        }

        if (memcpy_s(buffer, size, readData, size) != EOK) {
            free(buffer);
            return -1;
        }
        if (data != nullptr) {
            free(const_cast<void*>(data));
            data = nullptr;
        }

        data = buffer;
        return 0;
    }
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_RAWDATA_BUFFER_H
