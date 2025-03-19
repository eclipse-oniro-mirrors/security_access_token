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
class MockNativeToken {
public:
    explicit MockNativeToken(const std::string& process);
    ~MockNativeToken();
private:
    uint64_t selfToken_;
};

class MockHapToken {
public:
    explicit MockHapToken(
        const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp = true);
    ~MockHapToken();
private:
    uint64_t selfToken_;
    uint32_t mockToken_;
};

class TestCommon {
public:
    static constexpr int32_t DEFAULT_API_VERSION = 12;

    static void SetTestEvironment(uint64_t shellTokenId);
    static void ResetTestEvironment();
    static uint64_t GetShellTokenId();

    static void GetHapParams(HapInfoParams& infoParams, HapPolicyParams& policyParams);
    static void TestPreparePermStateList(HapPolicyParams &policy);
    static void TestPreparePermDefList(HapPolicyParams &policy);
    static void TestPrepareKernelPermissionStatus(HapPolicyParams& policyParams);
    static HapPolicyParams GetTestPolicyParams();
    static HapInfoParams GetInfoManagerTestInfoParms();
    static HapInfoParams GetInfoManagerTestNormalInfoParms();
    static HapInfoParams GetInfoManagerTestSystemInfoParms();
    static HapPolicyParams GetInfoManagerTestPolicyPrams();

    static int32_t AllocTestHapToken(const HapInfoParams& hapInfo,
        HapPolicyParams& hapPolicy, AccessTokenIDEx& tokenIdEx);
    static AccessTokenIDEx AllocAndGrantHapTokenByTest(const HapInfoParams& info, HapPolicyParams& policy);
    static int32_t DeleteTestHapToken(AccessTokenID tokenID);
    static void GetNativeTokenTest();
    static uint64_t GetNativeToken(const char* processName, const char** perms, int32_t permNum);
    static AccessTokenID GetNativeTokenIdFromProcess(const std::string& process);
    static AccessTokenIDEx GetHapTokenIdFromBundle(
        int32_t userID, const std::string& bundleName, int32_t instIndex);
    static int32_t GrantPermissionByTest(AccessTokenID tokenID, const std::string& permission, uint32_t flag);
    static int32_t RevokePermissionByTest(AccessTokenID tokenID, const std::string& permission, uint32_t flag);
    static int32_t GetReqPermissionsByTest(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& permStatList, bool isSystemGrant);
    static int32_t GetPermissionFlagByTest(AccessTokenID tokenID, const std::string& permission, uint32_t& flag);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // TEST_COMMON_H
