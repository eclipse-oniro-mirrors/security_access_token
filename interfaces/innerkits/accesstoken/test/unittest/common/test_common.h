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

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TestCommon {
public:
    static constexpr int32_t DEFAULT_API_VERSION = 12;

    static void GetHapParams(HapInfoParams& infoParams, HapPolicyParams& policyParams);
    static void TestPreparePermStateList(HapPolicyParams &policy);
    static void TestPreparePermDefList(HapPolicyParams &policy);
    static void TestPrepareKernelPermissionDefinition(
        HapInfoParams& infoParams, HapPolicyParams& policyParams);
    static void TestPrepareKernelPermissionStatus(HapPolicyParams& policyParams);
    static HapPolicyParams GetTestPolicyParams();
    static HapInfoParams GetInfoManagerTestInfoParms();
    static HapInfoParams GetInfoManagerTestNormalInfoParms();
    static HapInfoParams GetInfoManagerTestSystemInfoParms();
    static HapPolicyParams GetInfoManagerTestPolicyPrams();
    static AccessTokenID AllocTestToken(const HapInfoParams& hapInfo, const HapPolicyParams& hapPolicy);
    static void GetNativeTokenTest();
    static uint64_t GetNativeToken(const char *processName, const char **perms, int32_t permNum);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // TEST_COMMON_H
