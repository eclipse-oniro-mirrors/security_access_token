/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "setremotenativetokeninfo_fuzzer.h"

#include <string>
#include <vector>
#include <thread>
#include "accesstoken_fuzzdata.h"
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool SetRemoteNativeTokenInfoFuzzTest(const uint8_t* data, size_t size)
    {
#ifdef TOKEN_SYNC_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);
        NativeTokenInfoForSync native1 = {
            .baseInfo.apl = APL_NORMAL,
            .baseInfo.ver = 1,
            .baseInfo.processName = fuzzData.GenerateRandomString(),
            .baseInfo.dcap = {fuzzData.GenerateRandomString(), fuzzData.GenerateRandomString()},
            .baseInfo.tokenID = fuzzData.GetData<AccessTokenID>(),
            .baseInfo.tokenAttr = 0,
            .baseInfo.nativeAcls = {fuzzData.GenerateRandomString()},
        };

        std::vector<NativeTokenInfoForSync> nativeTokenInfoList;
        nativeTokenInfoList.emplace_back(native1);

        int32_t result = AccessTokenKit::SetRemoteNativeTokenInfo(fuzzData.GenerateRandomString(), nativeTokenInfoList);
        return result == RET_SUCCESS;
#else
        return true;
#endif
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetRemoteNativeTokenInfoFuzzTest(data, size);
    return 0;
}