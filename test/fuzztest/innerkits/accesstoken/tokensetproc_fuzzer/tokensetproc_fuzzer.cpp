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

#include <cstdint>
#include <string>
#include <vector>

#include "accesstoken_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "securec.h"
#include "spm_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr uint32_t MAX_SPM_NAME_SIZE = 256;
constexpr uint32_t MAX_SPM_PERM_BUF_SIZE = 256;
constexpr uint32_t MAX_EXTERN_ENTRY_COUNT = 3;
constexpr uint32_t MAX_EXTERN_VALUE_SIZE = 32;

void AppendUint32(std::vector<char>& raw, uint32_t value)
{
    char bytes[sizeof(uint32_t)] = {0};
    if (memcpy_s(bytes, sizeof(bytes), &value, sizeof(value)) != EOK) {
        return;
    }
    raw.insert(raw.end(), bytes, bytes + sizeof(bytes));
}

void FuzzSpmGetEntry(FuzzedDataProvider& provider)
{
    AccessTokenID consumeTokenID = ConsumeTokenId(provider);
    SpmData* spmDataNew = SpmDataNew(MAX_SPM_PERM_BUF_SIZE, MAX_SPM_PERM_BUF_SIZE, MAX_SPM_NAME_SIZE);
    if (spmDataNew == nullptr) {
        return;
    }
    (void)SpmGetEntry(static_cast<uint32_t>(consumeTokenID), spmDataNew);
    SpmDataFree(spmDataNew);
}

void FuzzTransferSpmExternPerms(FuzzedDataProvider& provider)
{
    uint32_t entryCount = provider.ConsumeIntegralInRange<uint32_t>(1, MAX_EXTERN_ENTRY_COUNT);
    std::vector<char> raw;
    for (uint32_t i = 0; i < entryCount; ++i) {
        uint32_t key = provider.ConsumeIntegral<uint32_t>();
        std::string value = provider.ConsumeRandomLengthString(MAX_EXTERN_VALUE_SIZE);
        value.push_back('\0');
        uint32_t valueSize = static_cast<uint32_t>(value.size());

        AppendUint32(raw, key);
        AppendUint32(raw, valueSize);
        raw.insert(raw.end(), value.begin(), value.end());
    }

    if (raw.empty()) {
        return;
    }

    SpmBlob data = {
        .buf = raw.data(),
        .bufSize = static_cast<uint32_t>(raw.size()),
    };
    std::vector<PermsWithValue> valueList(entryCount);
    uint32_t listSize = entryCount;
    (void)TransferSpmExternPerms(&data, valueList.data(), &listSize);
}

void FuzzSpmRefCnt(FuzzedDataProvider& provider)
{
    uint32_t uid = provider.ConsumeIntegral<uint32_t>();
    uint32_t spawnId = provider.ConsumeIntegral<uint32_t>();
    AccessTokenID consumeTokenID = ConsumeTokenId(provider);
    uint64_t uidRefCnt = 0;
    uint64_t tokenIdRefCnt = 0;

    (void)SpmIncUidRefCnt(uid, spawnId);
    (void)SpmGetUidRefCnt(uid, &uidRefCnt);
    (void)SpmDecUidRefCnt(uid, spawnId);

    (void)SpmIncTokenidRefCnt(static_cast<uint32_t>(consumeTokenID), spawnId);
    (void)SpmGetTokenidRefCnt(static_cast<uint32_t>(consumeTokenID), &tokenIdRefCnt);
    (void)SpmDecTokenidRefCnt(static_cast<uint32_t>(consumeTokenID), spawnId);
}
} // namespace

bool TokenSetprocFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    FuzzSpmGetEntry(provider);
    FuzzTransferSpmExternPerms(provider);
    FuzzSpmRefCnt(provider);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::TokenSetprocFuzzTest(data, size);
    return 0;
}
