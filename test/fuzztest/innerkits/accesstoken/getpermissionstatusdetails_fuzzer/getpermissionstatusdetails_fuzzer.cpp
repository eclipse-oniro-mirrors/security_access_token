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

#include "getpermissionstatusdetails_fuzzer.h"

#include <climits>
#include <string>
#include <vector>

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr int32_t TEST_USER_ID = 0;
constexpr int32_t DEFAULT_API_VERSION = 8;
constexpr uint32_t MAX_PERMISSION_LIST_SIZE = 1025;
const std::string TEST_BUNDLE_NAME = "getpermissionstatusdetails.fuzzer";
const std::string VALID_PERMISSION_NAME = "ohos.permission.INTERNET";
const std::string UNDECLARED_PERMISSION_NAME = "ohos.permission.CAMERA";
const std::string INVALID_PERMISSION_NAME = "ohos.permission.BETA";

void InitHapInfoParams(HapInfoParams& info)
{
    info.userID = TEST_USER_ID;
    info.bundleName = TEST_BUNDLE_NAME;
    info.instIndex = 0;
    info.dlpType = static_cast<int32_t>(HapDlpType::DLP_COMMON);
    info.appIDDesc = "fuzzer";
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    info.appDistributionType = "";
    info.isRestore = false;
    info.tokenID = 0;
    info.isAtomicService = false;
}

void InitHapPolicy(HapPolicyParams& policy)
{
    PermissionDef def = {
        .permissionName = VALID_PERMISSION_NAME,
        .bundleName = TEST_BUNDLE_NAME,
        .grantMode = static_cast<int32_t>(GrantMode::USER_GRANT),
        .availableLevel = ATokenAplEnum::APL_NORMAL,
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
    PermissionStateFull state = {
        .permissionName = VALID_PERMISSION_NAME,
        .isGeneral = true,
        .resDeviceID = { "local" },
        .grantStatus = { PermissionState::PERMISSION_DENIED },
        .grantFlags = { PermissionFlag::PERMISSION_DEFAULT_FLAG },
    };
    policy.apl = ATokenAplEnum::APL_NORMAL;
    policy.domain = "test_domain";
    policy.permList = { def };
    policy.permStateList = { state };
}

AccessTokenID EnsureValidHapTokenId()
{
    static AccessTokenID tokenIdValue = INVALID_TOKENID;
    if (tokenIdValue != INVALID_TOKENID) {
        return tokenIdValue;
    }

    MockToken manageToken({ "ohos.permission.MANAGE_HAP_TOKENID" });
    HapInfoParams info;
    InitHapInfoParams(info);
    HapPolicyParams policy;
    InitHapPolicy(policy);
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(info, policy);
    tokenIdValue = tokenIdEx.tokenIdExStruct.tokenID;
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
}

bool GetPermissionStatusDetailsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    AccessTokenID validTokenId = EnsureValidHapTokenId();
    if (validTokenId == INVALID_TOKENID) {
        return false;
    }

    MockToken queryToken({ "ohos.permission.GET_SENSITIVE_PERMISSIONS" }, false);
    FuzzedDataProvider provider(data, size);
    AccessTokenID tokenId = provider.ConsumeBool() ? validTokenId : ConsumeTokenId(provider);
    std::vector<std::string> permissionList = ConsumePermissionList(provider);
    std::vector<PermissionStatusDetail> resultList;
    int32_t ret = AccessTokenKit::GetPermissionStatusDetails(tokenId, permissionList, resultList);
    if (ret == RET_SUCCESS) {
        for (const auto& result : resultList) {
            (void)result.permissionName;
            (void)result.grantStatus;
            (void)result.grantFlag;
            (void)result.resultType;
        }
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetPermissionStatusDetailsFuzzTest(data, size);
    return 0;
}
