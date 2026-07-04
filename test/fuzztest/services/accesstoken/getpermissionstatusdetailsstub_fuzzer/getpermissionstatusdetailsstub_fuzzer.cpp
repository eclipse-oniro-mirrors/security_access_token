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

#include "getpermissionstatusdetailsstub_fuzzer.h"

#include <string>
#include <vector>

#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "mock_permission.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr int32_t TEST_USER_ID = 0;
constexpr int32_t DEFAULT_API_VERSION = 8;
constexpr uint32_t MAX_PERMISSION_LIST_SIZE = 1025;
constexpr uint32_t COMMAND_GET_PERMISSION_STATUS_DETAILS_CODE = 205;
const std::string TEST_BUNDLE_NAME = "getpermissionstatusdetailsstub.fuzzer";
const std::string VALID_PERMISSION_NAME = "ohos.permission.INTERNET";
const std::string UNDECLARED_PERMISSION_NAME = "ohos.permission.CAMERA";
const std::string INVALID_PERMISSION_NAME = "ohos.permission.BETA";

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
    PermissionDef def = {
        .permissionName = VALID_PERMISSION_NAME,
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = static_cast<int32_t>(GrantMode::USER_GRANT),
        .availableLevel = ATokenAplEnum::APL_SYSTEM_CORE,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "label",
        .labelId = 0,
        .description = "description",
        .descriptionId = 0,
        .availableType = ATokenAvailableTypeEnum::NORMAL,
        .isKernelEffect = false,
        .hasValue = false,
    };
    PermissionStatus state = {
        .permissionName = VALID_PERMISSION_NAME,
        .grantStatus = PermissionState::PERMISSION_DENIED,
        .grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG,
    };
    policy.apl = APL_SYSTEM_CORE;
    policy.domain = "test_domain";
    policy.permList = { def };
    policy.permStateList = { state };
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

std::vector<std::string> ConsumePermissionList(FuzzedDataProvider& provider)
{
    if (provider.ConsumeBool()) {
        return { VALID_PERMISSION_NAME, UNDECLARED_PERMISSION_NAME, INVALID_PERMISSION_NAME };
    }
    uint32_t listSize = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_PERMISSION_LIST_SIZE);
    std::vector<std::string> permissionList;
    permissionList.reserve(listSize);
    for (uint32_t i = 0; i < listSize; ++i) {
        if (provider.ConsumeBool()) {
            permissionList.emplace_back(ConsumePermissionName(provider));
        } else {
            permissionList.emplace_back(provider.ConsumeRandomLengthString());
        }
    }
    return permissionList;
}

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}

bool ReadReplyErrCode(MessageParcel& reply, int32_t& errCode)
{
    errCode = RET_FAILED;
    return reply.ReadInt32(errCode);
}

bool ReadPermissionStatusDetail(MessageParcel& reply)
{
    std::u16string permissionName;
    int32_t grantStatus = PERMISSION_DENIED;
    uint32_t grantFlag = PERMISSION_DEFAULT_FLAG;
    int32_t resultType = static_cast<int32_t>(PermissionResultType::PERMISSION_VALID);
    return reply.ReadString16(permissionName) && reply.ReadInt32(grantStatus) &&
        reply.ReadUint32(grantFlag) && reply.ReadInt32(resultType);
}

bool ReadPermissionStatusDetailList(MessageParcel& reply)
{
    int32_t resultListSize = 0;
    if (!reply.ReadInt32(resultListSize) || resultListSize < 0 ||
        resultListSize > static_cast<int32_t>(MAX_PERMISSION_LIST_SIZE)) {
        return false;
    }
    for (int32_t index = 0; index < resultListSize; ++index) {
        if (!ReadPermissionStatusDetail(reply)) {
            return false;
        }
    }
    return true;
}
}

bool GetPermissionStatusDetailsStubFuzzTest(const uint8_t* data, size_t size)
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
    std::vector<std::string> permissionList = ConsumePermissionList(provider);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteUint32(tokenId) || !datas.WriteStringVector(permissionList)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MockToken mockToken({ "ohos.permission.GET_SENSITIVE_PERMISSIONS" }, false);
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        COMMAND_GET_PERMISSION_STATUS_DETAILS_CODE, datas, reply, option);
    int32_t errCode = RET_FAILED;
    if (!ReadReplyErrCode(reply, errCode)) {
        return false;
    }
    if (errCode == RET_SUCCESS && !ReadPermissionStatusDetailList(reply)) {
        return false;
    }
    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    OHOS::Initialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetPermissionStatusDetailsStubFuzzTest(data, size);
    return 0;
}
