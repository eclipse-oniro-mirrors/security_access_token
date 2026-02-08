/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include "accesstoken_dfx_define.h"
#include "accesstoken_common_log.h"
#include "hisysevent.h"
#include "parameter.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string ACCESSTOKEN_PROCESS_NAME = "accesstoken_service";
static constexpr char ADD_DOMAIN[] = "PERFORMANCE";
}

bool IsUEEnable()
{
    static constexpr int32_t VALUE_MAX_LEN = 8;
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter("persist.hiviewdfx.hiview.ue.enable", "", value, VALUE_MAX_LEN - 1);
    if (ret < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get parameter failed, ret=%{public}d.", ret);
        return false;
    }
    return std::atoi(value) == 1;
}

void ReportSysEventPerformance()
{
    // accesstoken_service add CPU_SCENE_ENTRY system event in OnStart, avoid CPU statistics
    long id = 1 << 0; // first scene
    int64_t time = AccessToken::TimeUtil::GetCurrentTimestamp();

    (void)HiSysEventWrite(ADD_DOMAIN, "CPU_SCENE_ENTRY", HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PACKAGE_NAME", ACCESSTOKEN_PROCESS_NAME, "SCENE_ID", std::to_string(id).c_str(), "HAPPEN_TIME", time);
}

void ReportSysEventServiceStart(const InitDfxInfo& info)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_SERVICE_START",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "PID", info.pid,
        "HAP_SIZE", info.hapSize,
        "NATIVE_SIZE", info.nativeSize,
        "PERM_DEFINITION_SIZE", info.permDefSize,
        "DLP_PERMISSION_SIZE", info.dlpSize,
        "PARSE_CONFIG_FLAG", info.parseConfigFlag);
}

void ReportSysEventServiceStartError(SceneCode scene, const std::string& errMsg, int32_t errCode)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_SERVICE_START_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", scene, "ERROR_CODE", errCode, "ERROR_MSG", errMsg);
}

void ReportSysCommonEventError(int32_t ipcCode, int32_t errCode)
{
    if (GetThreadErrorMsgLen() == 0) {
        return;
    }
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_EXCEPTION",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", ipcCode, "ERROR_CODE", errCode,
        "ERROR_MSG", GetThreadErrorMsg());
    ClearThreadErrorMsg();
}

void ReportSysEventAddHap(int32_t errorCode, const HapDfxInfo& info, bool needReportFault)
{
    if (!IsUEEnable()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "UE is not enable.");
        return;
    }
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ADD_HAP",
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
    if (needReportFault) {
        ReportSysCommonEventError(info.ipcCode, errorCode);
    }
}

void ReportSysEventUpdateHap(int32_t errorCode, const HapDfxInfo& info)
{
    if (!IsUEEnable()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "UE is not enable.");
        return;
    }
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_HAP",
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
    ReportSysCommonEventError(info.ipcCode, errorCode);
}

void ReportSysEventDelHap(int32_t errorCode, const HapDfxInfo& info)
{
    if (!IsUEEnable()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "UE is not enable.");
        return;
    }
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "DEL_HAP",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "TOKENID", info.tokenId,
        "USERID", info.userID,
        "BUNDLENAME", info.bundleName,
        "INSTINDEX", info.instIndex,
        "SCENE_CODE", CommonSceneCode::AT_COMMON_FINISH,
        "ERROR_CODE", errorCode,
        "DURATION", info.duration);
    ReportSysCommonEventError(info.ipcCode, errorCode);
}

void ReportSysEventDbException(AccessTokenDbSceneCode sceneCode, int32_t errCode, const std::string& tableName)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "DATABASE_EXCEPTION",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", sceneCode, "ERROR_CODE", errCode,
        "TABLE_NAME", tableName);
}

void ReportPermissionVerifyEvent(AccessTokenID callerTokenId, const std::string& permissionName,
    const std::string& interfaceName)
{
    if (interfaceName.empty()) {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callerTokenId, "PERMISSION_NAME", permissionName);
    } else {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callerTokenId, "PERMISSION_NAME", permissionName,
            "INTERFACE", interfaceName);
    }
}

void ReportSetPermDialogCapEvent(const PermDialogCapInfo& info)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "SET_PERMISSION_DIALOG_CAP",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "TOKENID", info.tokenId,
        "USERID", info.userID, "BUNDLENAME", info.bundleName,
        "INSTINDEX", info.instIndex, "ENABLE", info.enable);
}

void ReportPermissionCheckDetailEvent(const PermissionCheckEventInfo& info)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", info.code,
        "CALLER_TOKENID", info.callerTokenId, "PERMISSION_NAME", info.permissionName,
        "FLAG", info.flag, "PERMISSION_GRANT_TYPE", info.changeType);
}

void ReportUpdatePermStatusErrorEvent(const UpdatePermStatusErrorInfo& info)
{
    if (info.needKill) {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_PERMISSION_STATUS_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", info.errorCode, "TOKENID",
            info.tokenId, "PERM", info.permissionName, "BUNDLE_NAME", info.bundleName,
            "INT_VAL1", info.val1, "INT_VAL2", info.val2, "NEED_KILL", info.needKill);
    } else {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_PERMISSION_STATUS_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", info.errorCode,
            "TOKENID", info.tokenId, "PERM", info.permissionName, "BUNDLE_NAME", info.bundleName);
    }
}

void ReportUpdatePermissionEvent(const UpdatePermissionInfo& info)
{
    if (info.bundleName.empty()) {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_PERMISSION",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "SCENE_CODE", info.sceneCode,
            "TOKENID", info.tokenId, "PERMISSION_NAME", info.permissionName,
            "PERMISSION_FLAG", info.permissionFlag, "GRANTED_FLAG", info.grantedFlag);
    } else {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_PERMISSION",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "SCENE_CODE", info.sceneCode,
            "TOKENID", info.tokenId, "USERID", info.userID, "BUNDLENAME", info.bundleName,
            "INSTINDEX", info.instIndex, "PERMISSION_NAME", info.permissionName,
            "PERMISSION_FLAG", info.permissionFlag, "GRANTED_FLAG", info.grantedFlag);
    }
}

void ReportPermissionCheckEvent(int32_t code, const std::string& errorReason)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
        HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", code, "ERROR_REASON", errorReason);
}

void ReportPermissionSyncEvent(int32_t code, const std::string& remoteId, const std::string& errorReason)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_SYNC",
        HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", code, "REMOTE_ID", remoteId, "ERROR_REASON", errorReason);
}

void ReportClearUserPermStateEvent(AccessTokenID tokenId, uint32_t tokenIdListSize)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "CLEAR_USER_PERMISSION_STATE",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "TOKENID", tokenId, "TOKENID_LEN", tokenIdListSize);
}

void ReportPermDialogStatusEvent(int32_t userID, const std::string& permissionName, int32_t toggleStatus)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERM_DIALOG_STATUS_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "USERID", userID,
        "PERMISSION_NAME", permissionName, "TOGGLE_STATUS", toggleStatus);
}

void ReportGrantTempPermissionEvent(AccessTokenID tokenId, const std::string& permissionName)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "GRANT_TEMP_PERMISSION",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "TOKENID", tokenId, "PERMISSION_NAME", permissionName);
}

void ReportPermStoreResultEvent(AccessTokenID tokenId, const std::string& permissionName)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
        HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", PERMISSION_STORE_ERROR,
        "CALLER_TOKENID", tokenId, "PERMISSION_NAME", permissionName);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS