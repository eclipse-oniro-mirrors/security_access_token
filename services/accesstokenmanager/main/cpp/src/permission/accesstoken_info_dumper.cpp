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

#include "accesstoken_info_dumper.h"

#include <unordered_set>

#include "accesstoken_common_log.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "access_token_error.h"
#include "constant_common.h"
#include "json_parse_loader.h"
#include "libraryloader.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
void AccessTokenInfoDumper::DumpHapTokenInfoByTokenId(AccessTokenID tokenId, std::string& dumpInfo)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(tokenId);
    if (type == TOKEN_HAP) {
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        dumpInfo = (infoPtr != nullptr) ? infoPtr->ToString() : "Error: TokenID does not exist.\n";
        return;
    }
    if (type == TOKEN_NATIVE || type == TOKEN_SHELL) {
        dumpInfo = NativeTokenToString(tokenId);
        return;
    }
    dumpInfo = "Error: TokenID does not exist.\n";
}

void AccessTokenInfoDumper::DumpHapTokenInfoByBundleName(const std::string& bundleName, std::string& dumpInfo)
{
    std::unordered_set<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetAllHapTokenId(tokenIdList);
    bool found = false;
    for (const auto tokenId : tokenIdList) {
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        if (infoPtr == nullptr || bundleName != infoPtr->GetBundleName()) {
            continue;
        }
        dumpInfo.append(infoPtr->ToString());
        dumpInfo.append("\n");
        found = true;
    }
    if (!found) {
        dumpInfo = "Error: BundleName '" + bundleName + "' does not exist.\n";
    }
}

void AccessTokenInfoDumper::DumpAllHapTokenName(std::string& dumpInfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Get all hap token name.");

    std::unordered_set<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetAllHapTokenId(tokenIdList);
    for (const auto tokenId : tokenIdList) {
        HapTokenInfo info;
        if (AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenId, info) != RET_SUCCESS) {
            continue;
        }
        dumpInfo += std::to_string(info.tokenID) + ": " + info.bundleName;
        dumpInfo.append("\n");
    }
}

void AccessTokenInfoDumper::DumpNativeTokenInfoByProcessName(const std::string& processName, std::string& dumpInfo)
{
    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId(processName);
    if (tokenId == INVALID_TOKENID) {
        dumpInfo = "Error: ProcessName '" + processName + "' does not exist.\n";
        return;
    }
    dumpInfo = NativeTokenToString(tokenId);
}

void AccessTokenInfoDumper::DumpAllNativeTokenName(std::string& dumpInfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Get all native token name.");

    std::unordered_set<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetAllNativeTokenId(tokenIdList);
    for (const auto tokenId : tokenIdList) {
        NativeTokenInfoBase info;
        if (AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenId, info) != RET_SUCCESS) {
            continue;
        }
        dumpInfo += std::to_string(tokenId) + ": " + info.processName;
        dumpInfo.append("\n");
    }
}

std::string AccessTokenInfoDumper::NativeTokenToString(AccessTokenID tokenId)
{
    std::vector<NativeTokenInfoBase> tokenInfos;
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return "";
    }
    int32_t ret = policy->GetAllNativeTokenInfo(tokenInfos);
    if (ret != RET_SUCCESS || tokenInfos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to load native from native json, err=%{public}d.", ret);
        return "";
    }
    for (const auto& nativeInfo : tokenInfos) {
        if (nativeInfo.tokenID == tokenId) {
            return policy->DumpNativeTokenInfo(nativeInfo);
        }
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}u is not exist.", tokenId);
    return "Error: TokenID does not exist.\n";
}

void AccessTokenInfoDumper::DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo)
{
    if (info.tokenId != 0) {
        DumpHapTokenInfoByTokenId(info.tokenId, dumpInfo);
        return;
    }

    if (!info.bundleName.empty()) {
        DumpHapTokenInfoByBundleName(info.bundleName, dumpInfo);
        return;
    }

    if (!info.processName.empty()) {
        DumpNativeTokenInfoByProcessName(info.processName, dumpInfo);
        return;
    }

    DumpAllHapTokenName(dumpInfo);
    DumpAllNativeTokenName(dumpInfo);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
