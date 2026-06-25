/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "getpermissionsstatusstub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>
#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "mock_permission.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "securec.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace {
std::unique_ptr<MockToken> g_mockToken;
constexpr int32_t TEST_USER_ID = 0;
constexpr int32_t DEFAULT_API_VERSION = 8;
const std::string TEST_BUNDLE_NAME = "getpermissionsstatusstub.fuzzer";
}

const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;

void InitValidHapInfoParams(HapInfoParams& param)
{
    param.userID = TEST_USER_ID;
    param.bundleName = TEST_BUNDLE_NAME;
    param.instIndex = 0;
    param.dlpType = static_cast<int32_t>(HapDlpType::DLP_COMMON);
    param.appIDDesc = "fuzzer";
    param.apiVersion = DEFAULT_API_VERSION;
    param.isSystemApp = false;
    param.appDistributionType = "";
    param.isRestore = false;
    param.tokenID = 0;
    param.isAtomicService = false;
}

void InitValidHapPolicy(HapPolicy& policy)
{
    policy.apl = APL_SYSTEM_CORE;
    policy.domain = "test_domain";
}

AccessTokenID EnsureValidTokenId()
{
    static AccessTokenID tokenIdValue = INVALID_TOKENID;
    if (tokenIdValue != INVALID_TOKENID) {
        return tokenIdValue;
    }

    HapInfoParcel hapInfoParcel;
    InitValidHapInfoParams(hapInfoParcel.hapInfoParameter);
    HapPolicyParcel hapPolicyParcel;
    InitValidHapPolicy(hapPolicyParcel.hapPolicy);

    uint64_t fullTokenIdValue = 0;
    int32_t ret = DelayedSingleton<AccessTokenManagerService>::GetInstance()->AllocHapToken(
        hapInfoParcel, hapPolicyParcel, fullTokenIdValue);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }
    AccessTokenIDEx fullTokenId = { .tokenIDEx = fullTokenIdValue };
    tokenIdValue = fullTokenId.tokenIdExStruct.tokenID;
    return tokenIdValue;
}

    bool GetPermissionsStatusStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenID validTokenId = EnsureValidTokenId();
        if (validTokenId == INVALID_TOKENID) {
            return false;
        }
        AccessTokenID tokenId = provider.ConsumeBool() ? validTokenId : ConsumeTokenId(provider);
        std::string permissionName = ConsumePermissionName(provider);
        PermissionListState perm = {
            .permissionName = permissionName,
            .state = static_cast<PermissionOper>(provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionOper::BUTT_OPER))),
        };
        PermissionListStateParcel permParcel;
        permParcel.permsState = perm;
        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        if (!datas.WriteInt32(1)) {
            return false;
        }
        if (!datas.WriteParcelable(&permParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_GET_PERMISSIONS_STATUS);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    void Initialize()
    {
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    g_mockToken.reset(new MockToken({ "ohos.permission.GET_SENSITIVE_PERMISSIONS" }, true, true));
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPermissionsStatusStubFuzzTest(data, size);
    return 0;
}
 
