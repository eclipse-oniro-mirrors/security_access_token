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

#ifndef FUZZ_SERVICE_CONTEXT_HELPER_H
#define FUZZ_SERVICE_CONTEXT_HELPER_H

#include <string>
#include <vector>

#include "access_token.h"
#define private public
#include "accesstoken_info_manager.h"
#include "accesstoken_manager_service.h"
#undef private
#include "generic_values.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace FuzzServiceContext {
constexpr int32_t DEFAULT_USER_ID = 0;
constexpr int32_t DEFAULT_INST_INDEX = 0;
constexpr int32_t DEFAULT_API_VERSION = 12;
constexpr uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);

inline PermissionStatus BuildGrantedPermissionStatus(const std::string& permissionName)
{
    return {
        .permissionName = permissionName,
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED,
    };
}

inline PermissionStatus BuildPermissionStatus(
    const std::string& permissionName, int32_t grantStatus, uint32_t grantFlag)
{
    return {
        .permissionName = permissionName,
        .grantStatus = grantStatus,
        .grantFlag = grantFlag,
    };
}

inline void FillSystemHapInfoTail(HapInfoParams& hapInfo, const std::string& bundleName);

inline HapInfoParams BuildSystemHapInfo(const std::string& bundleName)
{
    HapInfoParams hapInfo;
    hapInfo.userID = DEFAULT_USER_ID;
    hapInfo.bundleName = bundleName;
    hapInfo.instIndex = DEFAULT_INST_INDEX;
    FillSystemHapInfoTail(hapInfo, bundleName);
    return hapInfo;
}

inline void FillSystemHapInfoTail(HapInfoParams& hapInfo, const std::string& bundleName)
{
    hapInfo.dlpType = static_cast<int32_t>(HapDlpType::DLP_COMMON);
    hapInfo.appIDDesc = bundleName;
    hapInfo.apiVersion = DEFAULT_API_VERSION;
    hapInfo.isSystemApp = true;
}

inline HapPolicy BuildSystemHapPolicy(const std::string& permissionName)
{
    HapPolicy hapPolicy;
    hapPolicy.apl = APL_SYSTEM_BASIC;
    hapPolicy.domain = "fuzz_service_context_domain";
    hapPolicy.permStateList = {BuildGrantedPermissionStatus(permissionName)};
    return hapPolicy;
}

inline HapPolicy BuildSystemHapPolicy(const std::vector<PermissionStatus>& permissionStates)
{
    HapPolicy hapPolicy;
    hapPolicy.apl = APL_SYSTEM_BASIC;
    hapPolicy.domain = "fuzz_service_context_domain";
    hapPolicy.permStateList = permissionStates;
    return hapPolicy;
}

inline uint64_t GetSystemFullTokenId(const AccessTokenIDEx& tokenIdEx)
{
    return tokenIdEx.tokenIDEx | SYSTEM_APP_MASK;
}

inline uint64_t CreateSystemHapCaller(const std::string& bundleName, const std::string& permissionName)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapInfoParams hapInfo = BuildSystemHapInfo(bundleName);
    HapPolicy hapPolicy = BuildSystemHapPolicy(permissionName);
    std::vector<GenericValues> undefValues;
    if (AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfo, hapPolicy, tokenIdEx, undefValues) == RET_SUCCESS) {
        return GetSystemFullTokenId(tokenIdEx);
    }
    return 0;
}

inline uint64_t CreateSystemHapCaller(
    const std::string& bundleName, const std::vector<PermissionStatus>& permissionStates)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapInfoParams hapInfo = BuildSystemHapInfo(bundleName);
    HapPolicy hapPolicy = BuildSystemHapPolicy(permissionStates);
    std::vector<GenericValues> undefValues;
    if (AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfo, hapPolicy, tokenIdEx, undefValues) == RET_SUCCESS) {
        return GetSystemFullTokenId(tokenIdEx);
    }
    return 0;
}

inline void InitializeServiceCallerContext(uint64_t& callerFullTokenId, const std::string& bundleName,
    const std::string& permissionName)
{
    if (callerFullTokenId == 0) {
        callerFullTokenId = CreateSystemHapCaller(bundleName, permissionName);
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}

inline void InitializeServiceCallerContext(uint64_t& callerFullTokenId, const std::string& bundleName,
    const std::vector<PermissionStatus>& permissionStates)
{
    if (callerFullTokenId == 0) {
        callerFullTokenId = CreateSystemHapCaller(bundleName, permissionStates);
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}

inline AccessTokenID GetCallerTokenId(uint64_t callerFullTokenId)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = callerFullTokenId;
    return tokenIdEx.tokenIdExStruct.tokenID;
}

class CallingContextGuard final {
public:
    explicit CallingContextGuard(uint64_t callerFullTokenId) : originalTokenId_(GetSelfTokenID())
    {
        if (callerFullTokenId != 0) {
            (void)SetSelfTokenID(callerFullTokenId);
        }
    }

    ~CallingContextGuard()
    {
        (void)SetSelfTokenID(originalTokenId_);
    }

    CallingContextGuard(const CallingContextGuard&) = delete;
    CallingContextGuard& operator=(const CallingContextGuard&) = delete;

private:
    uint64_t originalTokenId_ = 0;
};
} // namespace FuzzServiceContext
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif
