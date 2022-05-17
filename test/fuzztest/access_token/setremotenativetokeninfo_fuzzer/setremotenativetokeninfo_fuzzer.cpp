/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool SetRemoteNativeTokenInfoFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;

#ifdef TOKEN_SYNC_ENABLE

        std::string testdata;
        if ((data == nullptr) || (size <= 0)) {
            return result;
        }
        if (size > 0) {
            testdata = reinterpret_cast<const char*>(data);
            AccessTokenID TOKENID = static_cast<AccessTokenID>(size);
            NativeTokenInfoForSync native1 = {
                .baseInfo.apl = APL_NORMAL,
                .baseInfo.ver = 1,
                .baseInfo.processName = testdata,
                .baseInfo.dcap = {testdata, testdata},
                .baseInfo.tokenID = TOKENID,
                .baseInfo.tokenAttr = 0,
                .baseInfo.nativeAcls = {testdata},
            };

            std::vector<NativeTokenInfoForSync> nativeTokenInfoList;
            nativeTokenInfoList.emplace_back(native1);

            result = AccessTokenKit::SetRemoteNativeTokenInfo(reinterpret_cast<const char*>(data), nativeTokenInfoList);
        }

#endif

        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetRemoteNativeTokenInfoFuzzTest(data, size);
    return 0;
}
