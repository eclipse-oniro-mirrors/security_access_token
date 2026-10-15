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

#include "install_sysevent_reporter.h"

#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "hap_token_info_inner.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

void InstallSysEventReporter::ReportSessionFinish(const InstallCache& cache, int64_t duration,
    int32_t sceneCode, int32_t errorCode)
{
    HapDfxInfo dfxInfoRaw;
    DumpPolicyEventInfo(cache.policy, dfxInfoRaw);
    dfxInfoRaw.ipcCode = cache.ipcCode;
    dfxInfoRaw.duration = duration;

    // success path does not attach FAULT: thread-local error msg, if any,
    // belongs to an unrelated request
    if (cache.HasNewIdentity()) {
        ReportAddHap(cache, sceneCode, errorCode, dfxInfoRaw, false);
    }

    for (auto it : cache.updatedBundlePolicyMap) {
        ReportUpdateHap(it.first, it.second, sceneCode, errorCode, dfxInfoRaw, false);
    }

    if (!cache.HasNewIdentity() && cache.updatedBundlePolicyMap.empty()) {
        HapDfxInfo dfxInfo = BuildDefaultDfxInfo(dfxInfoRaw);
        dfxInfo.tokenId = 0;
        dfxInfo.bundleName = cache.bundleParam.bundleName;
        dfxInfo.sceneCode = sceneCode;

        ReportSysEventAddHap(errorCode, dfxInfo, false);
    }
}

void InstallSysEventReporter::ReportSessionError(const InstallCache& cache,
    int32_t sceneCode, int32_t errorCode, AccessTokenID tokenId)
{
    // fault telemetry: no duration here, it belongs to event (success) reporting
    HapDfxInfo dfxInfoRaw;
    dfxInfoRaw.bundleName = cache.bundleParam.bundleName;
    if (dfxInfoRaw.bundleName.empty() && !cache.bundleInfos.empty()) {
        dfxInfoRaw.bundleName = cache.bundleInfos.front().GetBundleName();
    }
    dfxInfoRaw.sceneCode = sceneCode;
    dfxInfoRaw.ipcCode = cache.ipcCode;

    if (tokenId != 0) {
        // update-phase failure on a specific existing token: emit UPDATE_HAP directly
        // (not the reporter-internal ReportUpdateHap, which re-queries the cache and
        // may drop the event in rollback scenarios where the token is already gone)
        HapDfxInfo dfxInfo = BuildDefaultDfxInfo(dfxInfoRaw);
        dfxInfo.tokenId = tokenId;
        ReportSysEventUpdateHap(errorCode, dfxInfo, true);
    } else if (!cache.HasNewIdentity() && cache.updatedBundlePolicyMap.empty()) {
        // session-level failure without any token context: default ADD_HAP marker
        HapDfxInfo dfxInfo = BuildDefaultDfxInfo(dfxInfoRaw);
        dfxInfo.tokenId = 0;
        ReportSysEventAddHap(errorCode, dfxInfo, true);
    }

    if (cache.HasNewIdentity()) {
        ReportAddHap(cache, sceneCode, errorCode, dfxInfoRaw, true);
    }

    for (auto& it : cache.updatedBundlePolicyMap) {
        ReportUpdateHap(it.first, it.second, sceneCode, errorCode, dfxInfoRaw, true);
    }
}

void InstallSysEventReporter::ReportSessionTimeout(const InstallCache& cache, int64_t duration)
{
    // Timeout cleanup piggybacks on an unrelated request's thread: the thread-local
    // LOGC residue, if any, belongs to that request, so FAULT is never attached here.
    HapDfxInfo dfxInfoRaw;
    dfxInfoRaw.bundleName = cache.bundleParam.bundleName;
    if (dfxInfoRaw.bundleName.empty() && !cache.bundleInfos.empty()) {
        dfxInfoRaw.bundleName = cache.bundleInfos.front().GetBundleName();
    }
    dfxInfoRaw.sceneCode = InstallHapSceneCode::SESSION_TIMEOUT;
    dfxInfoRaw.ipcCode = cache.ipcCode;
    dfxInfoRaw.duration = duration; // survival time of the abandoned session

    if (cache.HasNewIdentity()) {
        ReportAddHap(cache, InstallHapSceneCode::SESSION_TIMEOUT, 0, dfxInfoRaw, false);
    }

    for (auto& it : cache.updatedBundlePolicyMap) {
        ReportUpdateHap(it.first, it.second, InstallHapSceneCode::SESSION_TIMEOUT, 0,
            dfxInfoRaw, false);
    }

    if (!cache.HasNewIdentity() && cache.updatedBundlePolicyMap.empty()) {
        HapDfxInfo dfxInfo = BuildDefaultDfxInfo(dfxInfoRaw);
        dfxInfo.tokenId = 0;
        ReportSysEventAddHap(0, dfxInfo, false);
    }
}

void InstallSysEventReporter::ReportAddHap(const InstallCache& cache, int32_t sceneCode,
    int32_t errorCode, const HapDfxInfo& dfxInfoRaw, bool needReportFault)
{
    HapDfxInfo dfxInfo = dfxInfoRaw;

    AccessTokenIDEx idEx;
    idEx.tokenIDEx = cache.identity.tokenId;

    dfxInfo.tokenId = idEx.tokenIdExStruct.tokenID;
    dfxInfo.tokenIdEx = idEx;

    // replace userID with uid
    dfxInfo.userID = cache.identity.uid;
    dfxInfo.bundleName = cache.baseInfo.bundleName;
    dfxInfo.instIndex = cache.baseInfo.instIndex;

    dfxInfo.sceneCode = sceneCode;
    dfxInfo.dlpType = static_cast<HapDlpType>(cache.bundlePolicy.dlpType);
    dfxInfo.isRestore = (cache.reserved != ReservedType::NONE);
    dfxInfo.oriTokenId = cache.oldTokenId;

    DumpPreAuthInfo(cache.bundlePolicy.preAuthorizationInfo, dfxInfo);
    ReportSysEventAddHap(errorCode, dfxInfo, needReportFault);
}

void InstallSysEventReporter::ReportUpdateHap(AccessTokenID tokenID, const BundlePolicy& bundlePolicy,
    int32_t sceneCode, int32_t errorCode, const HapDfxInfo& dfxInfoRaw, bool needReportFault)
{
    HapDfxInfo dfxInfo = dfxInfoRaw;
    dfxInfo.sceneCode = sceneCode;

    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
        return;
    }

    HapTokenInfo tokenInfo = infoPtr->GetHapInfoBasic();
    AccessTokenIDEx idEx;
    idEx.tokenIDEx = AccessTokenIDManager::BuildFullTokenId(tokenID, tokenInfo.tokenAttr);

    dfxInfo.tokenId = tokenID;
    dfxInfo.tokenIdEx = idEx;

    // replace userID with uid
    dfxInfo.userID = infoPtr->GetUid();
    dfxInfo.bundleName = tokenInfo.bundleName;
    dfxInfo.instIndex = tokenInfo.instIndex;

    DumpPreAuthInfo(bundlePolicy.preAuthorizationInfo, dfxInfo);
    ReportSysEventUpdateHap(errorCode, dfxInfo, needReportFault);
}

void InstallSysEventReporter::DumpPolicyEventInfo(const HapPolicy& policy, HapDfxInfo& dfxInfo)
{
    dfxInfo.permInfo = std::to_string(policy.permStateList.size()) + " : [";
    for (const auto& permState : policy.permStateList) {
        dfxInfo.permInfo.append(permState.permissionName + ", ");
    }
    dfxInfo.permInfo.append("]");

    dfxInfo.aclInfo = std::to_string(policy.aclRequestedList.size()) + " : [";
    for (const auto& perm : policy.aclRequestedList) {
        dfxInfo.aclInfo.append(perm + ", ");
    }
    dfxInfo.aclInfo.append("]");

    dfxInfo.extendInfo = std::to_string(policy.aclExtendedMap.size()) + " : {";
    for (const auto& aclExtend : policy.aclExtendedMap) {
        dfxInfo.extendInfo.append(aclExtend.first + ": " + aclExtend.second + ", ");
    }
    dfxInfo.extendInfo.append("}");
}

void InstallSysEventReporter::DumpPreAuthInfo(const std::vector<PreAuthorizationInfo>& preAuthorizationInfo,
    HapDfxInfo& dfxInfo)
{
    dfxInfo.preauthInfo = std::to_string(preAuthorizationInfo.size()) + " : [";
    for (const auto& preAuthInfo : preAuthorizationInfo) {
        dfxInfo.preauthInfo.append(preAuthInfo.permissionName + ", ");
    }
    dfxInfo.preauthInfo.append("]");
}

HapDfxInfo InstallSysEventReporter::BuildDefaultDfxInfo(const HapDfxInfo& dfxInfoRaw)
{
    HapDfxInfo dfxInfo = dfxInfoRaw;
    dfxInfo.tokenIdEx.tokenIDEx = 0;
    dfxInfo.userID = 0;
    dfxInfo.instIndex = 0;
    dfxInfo.dlpType = HapDlpType::DLP_COMMON;
    dfxInfo.isRestore = false;
    dfxInfo.oriTokenId = 0;
    return dfxInfo;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
