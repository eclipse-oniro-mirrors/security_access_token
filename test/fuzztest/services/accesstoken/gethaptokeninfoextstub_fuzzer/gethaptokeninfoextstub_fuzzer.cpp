/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "gethaptokeninfoextstub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>
#include <cstdlib>
#undef private
#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "permission_def_parcel.h"
#include "accesstoken_kit.h"
#include "access_token.h"
#include "permission_def.h"
#include "permission_state_full.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;
const int CONSTANTS_NUMBER_FIVE = 5;
static const int32_t ROOT_UID = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;

namespace OHOS {
    void TestPreparePermStateList(HapPolicyParams &policy)
    {
        PermissionStateFull permStatAlpha = {
            .permissionName = TEST_PERMISSION_NAME_ALPHA,
            .isGeneral = true,
            .resDeviceID = {"device3"},
            .grantStatus = {PermissionState::PERMISSION_DENIED},
            .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
        };
        PermissionStateFull permStatBeta = {
            .permissionName = TEST_PERMISSION_NAME_BETA,
            .isGeneral = true,
            .resDeviceID = {"device3"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
        };

        policy.permStateList.emplace_back(permStatAlpha);
        policy.permStateList.emplace_back(permStatBeta);
    }

    void TestPreparePermDefList(HapPolicyParams &policy)
    {
        PermissionDef permissionDefBeta;
        permissionDefBeta.permissionName = TEST_PERMISSION_NAME_BETA;
        permissionDefBeta.bundleName = TEST_BUNDLE_NAME;
        permissionDefBeta.grantMode = GrantMode::SYSTEM_GRANT;
        permissionDefBeta.availableLevel = APL_NORMAL;
        permissionDefBeta.provisionEnable = false;
        permissionDefBeta.distributedSceneEnable = false;

        PermissionDef permissionDefAlpha;
        permissionDefAlpha.permissionName = TEST_PERMISSION_NAME_ALPHA;
        permissionDefAlpha.bundleName = TEST_BUNDLE_NAME;
        permissionDefAlpha.grantMode = GrantMode::USER_GRANT;
        permissionDefAlpha.availableLevel = APL_NORMAL;
        permissionDefAlpha.provisionEnable = false;
        permissionDefAlpha.distributedSceneEnable = false;

        policy.permList.emplace_back(permissionDefBeta);
        policy.permList.emplace_back(permissionDefAlpha);
    }

    void SetHapTokenInfo(void)
    {
        HapInfoParams info = {
            .userID = TEST_USER_ID,
            .bundleName = TEST_BUNDLE_NAME,
            .instIndex = 0,
            .appIDDesc = "appIDDesc",
            .apiVersion = DEFAULT_API_VERSION
        };

        HapPolicyParams policy = {
            .apl = APL_NORMAL,
            .domain = "domain"
        };
        TestPreparePermDefList(policy);
        TestPreparePermStateList(policy);

        AccessTokenKit::AllocHapToken(info, policy);
    }

    void RemoveHapTokenInfo(void)
    {
        AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
        AccessTokenKit::DeleteToken(tokenID);
    }

    bool GetHapTokenInfoStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        SetHapTokenInfo();
        AccessTokenFuzzData fuzzData(data, size);
        AccessTokenID tokenId = 0;
        FuzzedDataProvider provider(data, size);
        if ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_FIVE) == 0) {
            tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
        } else {
            tokenId = fuzzData.GetData<AccessTokenID>();
        }

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_GET_HAP_TOKEN_INFO_EXTENSION);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            setuid(CONSTANTS_NUMBER_TWO);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(ROOT_UID);
        RemoveHapTokenInfo();
        return true;
    }

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetHapTokenInfoStubFuzzTest(data, size);
    return 0;
}
 
