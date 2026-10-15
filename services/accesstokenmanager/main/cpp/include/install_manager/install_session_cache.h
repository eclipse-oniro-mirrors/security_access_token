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

#ifndef INSTALL_SESSION_CACHE_H
#define INSTALL_SESSION_CACHE_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "access_token.h"
#include "hap_sign_verify_manager.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "accesstoken_id_manager.h"
#include "permission_data_brief.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct ResolvedUid {
    int32_t uid = 0;
    bool isNewBundleId = false;
    // true means the uid was adopted from the caller's input (UpdateHapPolicy uid param)
    bool fromCaller = false;
};

// IPC codes of install session phases, aligned with idl ipccode.
enum InstallIpcCode {
    IPC_PREPARE_HAP_IDENTITY = 82,
    IPC_UPDATE_HAP_POLICY = 83,
    IPC_FINISH_INSTALL = 84,
    IPC_CHECK_HAP_PERMISSION_INFO = 85,
    IPC_CHECK_HAP_SIGN_INFO = 88,
};

struct InstallCache {
    // Basic info:
    // Input hap list containing hap paths and user ID
    BundleHapList list;
    // Verified bundle info list; front elements from list signature verification,
    // back elements from database verification in MERGE scenario
    std::vector<TrustedBundleInfoInner> bundleInfos;
    // DB paths of the merge-surviving old modules, appended in MergeBundleInfos
    std::vector<std::string> oldModulePaths;
    // Hap policy containing permission state list
    HapPolicy policy;
    // Bundle parameters like bundleName, apl, etc.
    BundleParam bundleParam;
    // PID of the calling process for death monitoring
    int32_t callerPid = -1;
    // IPC code of the last phase entered (fault localization for FAULT events)
    int32_t ipcCode = -1;
    // Session creation timestamp for timeout cleanup
    int64_t createdMs = 0;
    // Session has finished permission check
    bool hasPermChecked = false;

    // Whether a new token identity was allocated this session (PrepareHapIdentity was
    // called), i.e. the session contains a newly installed hap. False for pure update
    // sessions that only go through UpdateHapPolicy.
    bool HasNewIdentity() const
    {
        return identity.tokenId != 0;
    }

    // Repair mode iff the desired plain 32-bit token id is non-zero
    bool IsRepairMode() const
    {
        return AccessTokenIDManager::ParseTokenId(repairedIdentity.tokenId) != 0;
    }

    // Install info:
    // Install type: TYPE_INSTALL, TYPE_REPLACE, or TYPE_MERGE
    InstallTypeEnum type;
    // Basic hap info for newly allocated tokenID: userID, bundleName, instIndex
    HapBaseInfo baseInfo;
    // Newly allocated tokenID and uid
    Identity identity;
    // Repair mode: desired identity from the BMS input (PrepareHapIdentity
    // identity in-out param) to re-create a drifted token; adopted only when
    // the caller passes a complete expectation (tokenId != 0 && uid != -1),
    // otherwise stays {0, -1} meaning no repair and no desired uid
    Identity repairedIdentity = {0, -1};
    // Bundle policy for newly allocated tokenID including pre-authorization and debug grant
    BundlePolicy bundlePolicy;
    // Whether bundleId in uid is newly allocated
    bool isNewBundleId = true;
    // True means the new identity uid was adopted from the caller's input
    // (PrepareHapIdentity identity.uid param); such tokens are marked migrated
    // to indicate the uid was designated by the caller
    bool uidFromCaller = false;
    // Reserved token flag: see ReservedType definition
    ReservedType reserved = ReservedType::NONE;
    // Old token ID for reserved != 0 scenario
    AccessTokenID oldTokenId = 0;
    // Old tokenAttr for reserved is 2
    int32_t oldAttr = 0;

    // Update info:
    // Policies of the tokens covered by this session's update plan, keyed by tokenId
    std::unordered_map<AccessTokenID, BundlePolicy> updatedBundlePolicyMap;
    // Resolved uid (and allocation state) per updated tokenId
    std::unordered_map<AccessTokenID, ResolvedUid> uidStateMap;
    // 会话级非活跃 token 快照（以 tokenId 为键）：
    // 更新链路经 GetHapTokenInfoForInstall 加载的 UNTRUSTED token DB 快照，
    // 同一会话内复用，避免重复读库。ACTIVE token 走 InfoManager 活跃缓存，
    // 不存这里。会话结束（提交/回滚）时随 InstallCache 一起释放。
    std::unordered_map<AccessTokenID, std::shared_ptr<HapTokenInfoInner>> untrustedTokenInfoMap;
    // 会话级 bundle→tokenId 索引快照（DB 行中状态为 ACTIVE 的 token）：
    // GetTokenIdAndUid 查询 token 表时顺带产出，供更新链路枚举同 bundle 的
    // 全部 token；纯更新会话（未经过 PrepareHapIdentity）由
    // SupplementUpdateInfo 兜底加载。会话结束时随 InstallCache 一起释放。
    std::vector<AccessTokenID> bundleTokenIdList;
    bool bundleTokenIdsLoaded = false;
};

struct FinishContext {
    BundleNoCachedInfo noCachedInfo;
    std::shared_ptr<BundleInfoInner> innerInfo;
    std::vector<HapTokenInfo> hapInfos;
    std::vector<std::vector<BriefPermData>> permBriefDataLists;
    std::vector<std::vector<PermissionWithValue>> extendPermLists;
    std::vector<std::shared_ptr<std::vector<BriefPermData>>> oldPermList;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // INSTALL_SESSION_CACHE_H
