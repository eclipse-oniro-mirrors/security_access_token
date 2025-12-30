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

#include "hisysevent_adapter.h"
#include "accesstoken_common_log.h"
#include "hisysevent.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string ACCESSTOKEN_PROCESS_NAME = "accesstoken_service";
static constexpr char ADD_DOMAIN[] = "PERFORMANCE";
}

void ReportSysEventPerformance()
{
    // accesstoken_service add CPU_SCENE_ENTRY system event in OnStart, avoid CPU statistics
    long id = 1 << 0; // first scene
    int64_t time = AccessToken::TimeUtil::GetCurrentTimestamp();

    int32_t ret = HiSysEventWrite(ADD_DOMAIN, "CPU_SCENE_ENTRY", HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PACKAGE_NAME", ACCESSTOKEN_PROCESS_NAME, "SCENE_ID", std::to_string(id).c_str(), "HAPPEN_TIME", time);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to report performance, ret %{public}d.", ret);
    }
}

void ReportSysEventServiceStart(const InitDfxInfo& info)
{
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_SERVICE_START",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "PID", info.pid,
        "HAP_SIZE", info.hapSize,
        "NATIVE_SIZE", info.nativeSize,
        "PERM_DEFINITION_SIZE", info.permDefSize,
        "DLP_PERMISSION_SIZE", info.dlpSize,
        "PARSE_CONFIG_FLAG", info.parseConfigFlag);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", ret);
    }
}

void ReportSysEventServiceStartError(SceneCode scene, const std::string& errMsg, int32_t errCode)
{
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_SERVICE_START_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", scene, "ERROR_CODE", errCode, "ERROR_MSG", errMsg);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", ret);
    }
}

void ReportSysCommonEventError(int32_t ipcCode, int32_t errCode)
{
    if (GetThreadErrorMsgLen() == 0) {
        return;
    }
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_EXCEPTION",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", ipcCode, "ERROR_CODE", errCode,
        "ERROR_MSG", GetThreadErrorMsg());
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", ret);
    }
    ClearThreadErrorMsg();
}

void ReportSysEventAddHap(int32_t errorCode, const HapDfxInfo& info, bool needReportFault)
{
    int32_t res = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ADD_HAP",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "SCENE_CODE", info.sceneCode,
        "TOKENID", info.tokenId,
        "ORI_TOKENID", info.oriTokenId,
        "TOKENIDEX", static_cast<uint64_t>(info.tokenIdEx.tokenIDEx),
        "USERID", info.userID,
        "BUNDLENAME", info.bundleName,
        "INSTINDEX", info.instIndex,
        "DLP_TYPE", info.dlpType,
        "IS_RESTORE", info.isRestore,
        "PERM_INFO", info.permInfo,
        "ACL_INFO", info.aclInfo,
        "PREAUTH_INFO", info.preauthInfo,
        "EXTEND_INFO", info.extendInfo,
        "DURATION", info.duration,
        "ERROR_CODE", errorCode);
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", res);
    }
    if (needReportFault) {
        ReportSysCommonEventError(info.ipcCode, errorCode);
    }
}

void ReportSysEventUpdateHap(int32_t errorCode, const HapDfxInfo& info)
{
    int32_t res = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_HAP",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "TOKENID", info.tokenId,
        "USERID", info.userID,
        "BUNDLENAME", info.bundleName,
        "INSTINDEX", info.instIndex,
        "SCENE_CODE", CommonSceneCode::AT_COMMON_FINISH,
        "ERROR_CODE", errorCode,
        "TOKENIDEX", static_cast<uint64_t>(info.tokenIdEx.tokenIDEx),
        "PERM_INFO", info.permInfo,
        "ACL_INFO", info.aclInfo,
        "PREAUTH_INFO", info.preauthInfo,
        "EXTEND_INFO", info.extendInfo,
        "DURATION", info.duration);
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", res);
    }
    ReportSysCommonEventError(info.ipcCode, errorCode);
}

void ReportSysEventDelHap(int32_t errorCode, int32_t sceneCode, const HapDfxInfo& info)
{
    int32_t res = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "DEL_HAP",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "TOKENID", info.tokenId,
        "USERID", info.userID,
        "BUNDLENAME", info.bundleName,
        "INSTINDEX", info.instIndex,
        "SCENE_CODE", sceneCode,
        "ERROR_CODE", errorCode,
        "DURATION", info.duration);
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", res);
    }
    ReportSysCommonEventError(info.ipcCode, errorCode);
}

void ReportSysEventDbException(AccessTokenDbSceneCode sceneCode, int32_t errCode, const std::string& tableName)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "DATABASE_EXCEPTION",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", sceneCode, "ERROR_CODE", errCode,
        "TABLE_NAME", tableName);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS