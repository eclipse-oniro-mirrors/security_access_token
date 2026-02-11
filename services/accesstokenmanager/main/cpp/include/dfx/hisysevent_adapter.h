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

#ifndef ACCESSTOKEN_HISYSEVENT_ADAPTER_H
#define ACCESSTOKEN_HISYSEVENT_ADAPTER_H

#include <string>
#include "access_token.h"
#include "accesstoken_dfx_define.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

// ===========================================
// Data Structures for HiSysEvent Reporting
// ===========================================

/**
 * @brief HAP token DFX information for add/update/delete operations
 * @details Contains token information for HAP lifecycle events
 */
struct HapDfxInfo {
    AccessTokenID tokenId = 0;              // Token ID
    AccessTokenIDEx tokenIdEx;              // Extended token ID
    AccessTokenID oriTokenId;               // Original token ID (before mapping)
    int32_t userID = 0;                     // User ID
    int32_t instIndex;                      // Instance index
    std::string bundleName;                 // Bundle name
    int64_t duration = 0;                   // Operation duration (ms)
    int32_t ipcCode = -1;                   // IPC interface code
    std::string permInfo;                   // Permission information (JSON string)
    std::string aclInfo;                    // ACL information (JSON string)
    std::string preauthInfo;                // Pre-auth information (JSON string)
    std::string extendInfo;                 // Extended information (JSON string)

    // Fields only for add operation
    int32_t sceneCode;                      // Scene code for the operation
    HapDlpType dlpType;                     // DLP type
    bool isRestore;                         // Whether it's a restore operation
};

/**
 * @brief Service initialization DFX information
 * @details Contains statistics for access token service startup
 */
struct InitDfxInfo {
    int32_t pid;                            // Process ID
    uint32_t hapSize;                       // Number of HAP tokens loaded
    uint32_t nativeSize;                    // Number of native tokens loaded
    uint32_t permDefSize;                   // Number of permission definitions loaded
    uint32_t dlpSize;                       // Number of DLP permissions loaded
    uint32_t parseConfigFlag;               // Config parsing flags
};

/**
 * @brief Permission dialog capability information
 * @details Used when setting permission dialog capability for a token
 */
struct PermDialogCapInfo {
    AccessTokenID tokenId = 0;              // Target token ID
    int32_t userID = 0;                     // User ID
    std::string bundleName;                 // Bundle name
    int32_t instIndex = 0;                  // Instance index
    bool enable = false;                    // Enable or disable dialog capability
};

/**
 * @brief Permission check event information
 * @details Used for reporting permission verification events with full details
 */
struct PermissionCheckEventInfo {
    int32_t code = 0;                       // Event code (from AccessTokenDfxCode)
    AccessTokenID callerTokenId = 0;        // Caller's token ID
    std::string permissionName;             // Permission name
    uint32_t flag = 0;                      // Permission flag
    int32_t changeType = 0;                 // Permission grant change type
};

/**
 * @brief Permission status update error information
 * @details Used when updating permission status fails
 */
struct UpdatePermStatusErrorInfo {
    int32_t errorCode = 0;                  // Error code
    AccessTokenID tokenId = 0;              // Target token ID
    std::string permissionName;             // Permission name
    std::string bundleName;                 // Bundle name
    int32_t val1 = 0;
    int32_t val2 = 0;
    bool needKill = false;                  // Whether process killing is needed
};

/**
 * @brief Permission update information
 * @details Used when permission status is successfully updated
 */
struct UpdatePermissionInfo {
    int32_t sceneCode = 0;                  // Scene code (start/finish)
    AccessTokenID tokenId = 0;              // Target token ID
    int32_t userID = 0;                     // User ID
    std::string bundleName;                 // Bundle name
    int32_t instIndex = 0;                  // Instance index
    std::string permissionName;             // Permission name
    uint32_t permissionFlag = 0;            // Permission flag
    bool grantedFlag = false;               // Whether permission is granted
};

// ===========================================
// Service Lifecycle Events
// ===========================================

/**
 * @brief Report performance event on service startup
 * @details Reports CPU_SCENE_ENTRY event to avoid CPU statistics missing
 */
void ReportSysEventPerformance();

/**
 * @brief Report service startup event
 * @param info Service initialization statistics including token counts
 */
void ReportSysEventServiceStart(const InitDfxInfo& info);

/**
 * @brief Report service startup error event
 * @param scene Scene code where error occurred
 * @param errMsg Error message
 * @param errCode Error code
 */
void ReportSysEventServiceStartError(SceneCode scene, const std::string& errMsg, int32_t errCode);

// ===========================================
// Common Error Events
// ===========================================

/**
 * @brief Report common exception event with thread error message
 * @details Reports ACCESSTOKEN_EXCEPTION event if thread error message exists
 * @param ipcCode IPC interface code
 * @param errCode Error code
 */
void ReportSysCommonEventError(int32_t ipcCode, int32_t errCode);

// ===========================================
// HAP Token Management Events
// ===========================================

/**
 * @brief Report HAP token addition event
 * @details Reports ADD_HAP event with full token information
 * @param errorCode Operation error code (RET_SUCCESS if success)
 * @param info HAP token DFX information
 * @param needReportFault Whether to report fault event separately
 */
void ReportSysEventAddHap(int32_t errorCode, const HapDfxInfo& info, bool needReportFault);

/**
 * @brief Report HAP token update event
 * @details Reports UPDATE_HAP event with updated token information
 * @param errorCode Operation error code (RET_SUCCESS if success)
 * @param info HAP token DFX information
 */
void ReportSysEventUpdateHap(int32_t errorCode, const HapDfxInfo& info);

/**
 * @brief Report HAP token deletion event
 * @details Reports DEL_HAP event when token is removed
 * @param errorCode Operation error code (RET_SUCCESS if success)
 * @param info HAP token DFX information
 */
void ReportSysEventDelHap(int32_t errorCode, const HapDfxInfo& info);

// ===========================================
// Permission Verification Events
// ===========================================

/**
 * @brief Report permission verification failure event
 * @details Reports PERMISSION_VERIFY_REPORT when caller lacks required permission
 * @param callerTokenId Caller's token ID
 * @param permissionName Permission name being verified
 * @param interfaceName Interface name where verification failed (optional)
 */
void ReportPermissionVerifyEvent(AccessTokenID callerTokenId, const std::string& permissionName,
    const std::string& interfaceName = "");

// ===========================================
// Permission Dialog Management Events
// ===========================================

/**
 * @brief Report permission dialog capability setting event
 * @details Reports SET_PERMISSION_DIALOG_CAP when dialog capability is changed
 * @param info Permission dialog capability information
 */
void ReportSetPermDialogCapEvent(const PermDialogCapInfo& info);

// ===========================================
// Permission Check Events
// ===========================================

/**
 * @brief Report permission check event with detailed information
 * @details Reports PERMISSION_CHECK_EVENT for user grant permission tracking
 * @param info Permission check event information
 */
void ReportPermissionCheckDetailEvent(const PermissionCheckEventInfo& info);

/**
 * @brief Report permission check event
 * @details Reports PERMISSION_CHECK when data validation fails
 * @param code Error code (from AccessTokenDfxCode)
 * @param errorReason Detailed error reason
 */
void ReportPermissionCheckEvent(int32_t code, const std::string& errorReason);

/**
 * @brief Report permission sync event
 * @details Reports PERMISSION_SYNC for cross-device token synchronization
 * @param code Sync error code
 * @param remoteId Remote device ID (encrypted)
 * @param errorReason Error reason for sync failure
 */
void ReportPermissionSyncEvent(int32_t code, const std::string& remoteId, const std::string& errorReason);

/**
 * @brief Report clear user permission state event
 * @details Reports CLEAR_USER_PERMISSION_STATE when user-granted permissions are cleared
 * @param tokenId Target token ID
 * @param tokenIdListSize Number of related tokens cleared
 */
void ReportClearUserPermStateEvent(AccessTokenID tokenId, uint32_t tokenIdListSize);

/**
 * @brief Report permission dialog status information
 * @details Reports PERM_DIALOG_STATUS_INFO for toggle status statistics
 * @param userID User ID
 * @param permissionName Permission name
 * @param toggleStatus Toggle status (OPEN/CLOSED)
 */
void ReportPermDialogStatusEvent(int32_t userID, const std::string& permissionName, int32_t toggleStatus);

/**
 * @brief Report temporary permission grant event
 * @details Reports GRANT_TEMP_PERMISSION when temporary permission is granted
 * @param tokenId Target token ID
 * @param permissionName Permission name
 */
void ReportGrantTempPermissionEvent(AccessTokenID tokenId, const std::string& permissionName);

// ===========================================
// Permission State Update Events
// ===========================================

/**
 * @brief Report permission status update error event
 * @details Reports UPDATE_PERMISSION_STATUS_ERROR when status update fails
 * @param info Update permission status error information
 */
void ReportUpdatePermStatusErrorEvent(const UpdatePermStatusErrorInfo& info);

/**
 * @brief Report permission update event
 * @details Reports UPDATE_PERMISSION when permission status is successfully updated
 * @param info Update permission information
 */
void ReportUpdatePermissionEvent(const UpdatePermissionInfo& info);

/**
 * @brief Report permission storage result event
 * @details Reports PERMISSION_CHECK when permission grant status storage fails
 * @param tokenId Target token ID
 * @param permissionName Permission name
 */
void ReportPermStoreResultEvent(AccessTokenID tokenId, const std::string& permissionName);

// ===========================================
// Database Events
// ===========================================

/**
 * @brief Report database exception event
 * @details Reports DATABASE_EXCEPTION when database operation fails
 * @param sceneCode Database operation scene code
 * @param errCode Database error code
 * @param tableName Affected table name
 */
void ReportSysEventDbException(AccessTokenDbSceneCode sceneCode, int32_t errCode, const std::string& tableName);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HISYSEVENT_ADAPTER_H
