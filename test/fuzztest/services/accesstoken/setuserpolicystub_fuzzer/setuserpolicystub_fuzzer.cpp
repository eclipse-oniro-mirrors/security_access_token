/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "setuserpolicystub_fuzzer.h"

#include <climits>
#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#include "access_token.h"
#include "accesstoken_id_manager.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_service_context_helper.h"
#include "hap_info_parcel.h"
#include "iaccess_token_manager.h"
#include "../../../common/mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr int32_t TEST_USER_ID = 0;
const std::string DEFAULT_CALLER_BUNDLE = "setuserpolicystub.fuzzer";
uint64_t g_callerFullTokenId = 0;
constexpr int32_t DEFAULT_API_VERSION = 8;
const std::string MANAGE_USER_POLICY_PERMISSION = "ohos.permission.MANAGE_USER_POLICY";
}

void InitHapInfoParams(HapInfoParams& param)
{
    param.userID = TEST_USER_ID;
    param.bundleName = DEFAULT_CALLER_BUNDLE;
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

void InitHapPolicy(HapPolicy& policy)
{
    policy.apl = APL_SYSTEM_CORE;
    policy.domain = "test_domain";
}

AccessTokenID EnsureTestHapToken()
{
    static AccessTokenID mockTokenId = INVALID_TOKENID;
    if (mockTokenId != INVALID_TOKENID) {
        return mockTokenId;
    }

    HapInfoParcel hapInfoParcel;
    InitHapInfoParams(hapInfoParcel.hapInfoParameter);
    HapPolicyParcel hapPolicyParcel;
    InitHapPolicy(hapPolicyParcel.hapPolicy);

    uint64_t fullTokenIdValue = 0;
    int32_t ret = DelayedSingleton<AccessTokenManagerService>::GetInstance()->AllocHapToken(
        hapInfoParcel, hapPolicyParcel, fullTokenIdValue);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }

    AccessTokenIDEx fullTokenId = { .tokenIDEx = fullTokenIdValue };
    mockTokenId = fullTokenId.tokenIdExStruct.tokenID;
    return mockTokenId;
}

void ClearUserPolicy(const string& permission)
{
    FuzzServiceContext::CallingContextGuard guard(g_callerFullTokenId);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteUint32(1)) {
        return;
    }
    if (!datas.WriteString(permission)) {
        return;
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_CLEAR_USER_POLICY), datas, reply, option);
}

void UpdatePolicyWhiteList(AccessTokenID tokenId, uint32_t permCode, int32_t type)
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteUint32(tokenId)) {
        return;
    }
    if (!datas.WriteUint32(permCode)) {
        return;
    }
    if (!datas.WriteInt32(type)) {
        return;
    }
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_UPDATE_POLICY_WHITE_LIST), datas, reply, option);
}

void GetPolicyWhiteList(uint32_t permCode)
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteUint32(permCode)) {
        return;
    }
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_POLICY_WHITE_LIST), datas, reply, option);
}

bool SetUserPolicyStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzServiceContext::CallingContextGuard guard(g_callerFullTokenId);
    FuzzedDataProvider provider(data, size);
    std::string permission = ConsumePermissionName(provider);

    UserPermissionPolicyIdl dataBlock;
    dataBlock.permissionName = permission;
    UserPolicyIdl userPolicyIdl;
    userPolicyIdl.userId = provider.ConsumeIntegralInRange<int32_t>(-1, INT_MAX),
    userPolicyIdl.isRestricted = provider.ConsumeBool();
    dataBlock.userPolicyList.emplace_back(userPolicyIdl);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteUint32(1)) {
        return false;
    }
    if (UserPermissionPolicyIdlBlockMarshalling(datas, dataBlock) != ERR_NONE) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_SET_USER_POLICY);

    MessageParcel reply;
    MessageOption option;
    AccessTokenID tokenId = EnsureTestHapToken();
    if (tokenId == INVALID_TOKENID) {
        return false;
    }
    MockToken mock({ MANAGE_USER_POLICY_PERMISSION });
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool UpdatePolicyWhiteListStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    std::string permission = ConsumePermissionName(provider);
    uint32_t permCode = 0;
    if (!AccessTokenKit::TransferPermissionToOpcode(permission, permCode)) {
        return false;
    }

    AccessTokenID randomTokenId = ConsumeTokenId(provider);
    AccessTokenID testTokenId = EnsureTestHapToken();
    if (testTokenId == INVALID_TOKENID) {
        return false;
    }
    MockToken mock({ MANAGE_USER_POLICY_PERMISSION });
    int32_t type = provider.ConsumeBool() ? static_cast<int32_t>(UpdateWhiteListType::ADD) :
        static_cast<int32_t>(UpdateWhiteListType::DELETE);
    UpdatePolicyWhiteList(randomTokenId, permCode, type);
    UpdatePolicyWhiteList(testTokenId, permCode, type);
    return true;
}

bool GetPolicyWhiteListStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    std::string permission = ConsumePermissionName(provider);
    uint32_t permCode = 0;
    if (!AccessTokenKit::TransferPermissionToOpcode(permission, permCode)) {
        return false;
    }

    if (EnsureTestHapToken() == INVALID_TOKENID) {
        return false;
    }
    MockToken mock({ MANAGE_USER_POLICY_PERMISSION });
    GetPolicyWhiteList(permCode);
    return true;
}

bool ClearUserPolicyStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    std::string permission = ConsumePermissionName(provider);
    if (EnsureTestHapToken() == INVALID_TOKENID) {
        return false;
    }
    MockToken mock({ MANAGE_USER_POLICY_PERMISSION });
    ClearUserPolicy(permission);
    return true;
}

void Initialize()
{
    FuzzServiceContext::InitializeServiceCallerContext(
        g_callerFullTokenId, DEFAULT_CALLER_BUNDLE, MANAGE_USER_POLICY_PERMISSION);
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
    OHOS::SetUserPolicyStubFuzzTest(data, size);
    OHOS::UpdatePolicyWhiteListStubFuzzTest(data, size);
    OHOS::GetPolicyWhiteListStubFuzzTest(data, size);
    OHOS::ClearUserPolicyStubFuzzTest(data, size);
    return 0;
}
