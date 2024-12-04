/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_RECORD_MANAGER_H
#define PERMISSION_RECORD_MANAGER_H

#include <vector>
#include <set>
#include <string>

#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "access_token.h"
#include "active_change_response_info.h"
#include "add_perm_param_info.h"
#include "app_manager_death_callback.h"
#include "app_manager_death_recipient.h"
#include "app_status_change_callback.h"
#include "hap_token_info.h"
#include "libraryloader.h"
#include "nocopyable.h"
#include "on_permission_used_record_callback.h"
#include "permission_record.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "permission_used_type_info.h"
#include "privacy_param.h"
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
#include "privacy_window_manager_agent.h"
#endif
#include "rwlock.h"
#include "safe_map.h"
#include "thread_pool.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyAppStateObserver : public ApplicationStateObserverStub {
public:
    PrivacyAppStateObserver() = default;
    ~PrivacyAppStateObserver() = default;
    void OnProcessDied(const ProcessData &processData) override;
    void OnAppStopped(const AppStateData &appStateData) override;
    void OnAppStateChanged(const AppStateData &appStateData) override;
    DISALLOW_COPY_AND_MOVE(PrivacyAppStateObserver);
};

class PrivacyAppManagerDeathCallback : public AppManagerDeathCallback {
public:
    PrivacyAppManagerDeathCallback() = default;
    ~PrivacyAppManagerDeathCallback() = default;

    void NotifyAppManagerDeath() override;
    DISALLOW_COPY_AND_MOVE(PrivacyAppManagerDeathCallback);
};

class PermissionRecordManager final {
public:
    static PermissionRecordManager& GetInstance();
    virtual ~PermissionRecordManager();

    void Init();
    int32_t AddPermissionUsedRecord(const AddPermParamInfo& info);
    void RemovePermissionUsedRecords(AccessTokenID tokenId);
    int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int32_t GetPermissionUsedRecordsAsync(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    int32_t StartUsingPermission(AccessTokenID tokenId, int32_t pid, const std::string& permissionName,
        PermissionUsedType type = PermissionUsedType::NORMAL_TYPE);
    int32_t StartUsingPermission(AccessTokenID tokenId, int32_t pid, const std::string& permissionName,
        const sptr<IRemoteObject>& callback, PermissionUsedType type = PermissionUsedType::NORMAL_TYPE);
    int32_t StopUsingPermission(AccessTokenID tokenId, int32_t pid, const std::string& permissionName);
    int32_t RegisterPermActiveStatusCallback(
        AccessTokenID regiterTokenId, const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback);
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback);

    void CallbackExecute(AccessTokenID tokenId, const std::string& permissionName, int32_t status,
        PermissionUsedType type = PermissionUsedType::NORMAL_TYPE);
    int32_t PermissionListFilter(const std::vector<std::string>& listSrc, std::vector<std::string>& listRes);
    bool IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName);
    int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfo>& results);
    int32_t SetMutePolicy(const PolicyType& policyType, const CallerType& callerType, bool isMute);
    int32_t SetEdmMutePolicy(const std::string permissionName, bool isMute);
    int32_t SetPrivacyMutePolicy(const std::string permissionName, bool isMute);
    int32_t SetTempMutePolicy(const std::string permissionName, bool isMute);
    int32_t SetHapWithFGReminder(uint32_t tokenId, bool isAllowed);

    void NotifyAppStateChange(AccessTokenID tokenId, int32_t pid, ActiveChangeType status);
    void SetLockScreenStatus(int32_t lockScreenStatus);
    int32_t GetLockScreenStatus(bool isIpc = false);

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    void NotifyCameraWindowChange(bool isPip, AccessTokenID tokenId, bool isShowing);
    void OnWindowMgrRemoteDied();
#endif
    void OnAppMgrRemoteDiedHandle();
    void OnAudioMgrRemoteDiedHandle();
    void OnCameraMgrRemoteDiedHandle();
    void RemoveRecordFromStartListByPid(const AccessTokenID tokenId, int32_t pid);
    void RemoveRecordFromStartListByToken(const AccessTokenID tokenId);
    void RemoveRecordFromStartListByOp(int32_t opCode);
    void ExecuteAllCameraExecuteCallback();
    void UpdatePermRecImmediately();

private:
    PermissionRecordManager();
    DISALLOW_COPY_AND_MOVE(PermissionRecordManager);

    bool IsAllowedUsingCamera(AccessTokenID tokenId);
    bool IsAllowedUsingMicrophone(AccessTokenID tokenId);

    void AddRecToCacheAndValueVec(const PermissionRecord& record, std::vector<GenericValues>& values);
    int32_t MergeOrInsertRecord(const PermissionRecord& record);
    bool UpdatePermissionUsedRecordToDb(const PermissionRecord& record);
    int32_t AddRecord(const PermissionRecord& record);
    int32_t GetPermissionRecord(const AddPermParamInfo& info, PermissionRecord& record);
    bool CreateBundleUsedRecord(const AccessTokenID tokenId, BundleUsedRecord& bundleRecord);
    void ExecuteDeletePermissionRecordTask();
    int32_t GetCurDeleteTaskNum();
    void AddDeleteTaskNum();
    void ReduceDeleteTaskNum();
    int32_t DeletePermissionRecord(int32_t days);

    void GetMergedRecordsFromCache(std::vector<PermissionRecord>& mergedRecords);
    void InsteadMergedRecIfNecessary(GenericValues& mergedRecord, std::vector<PermissionRecord>& mergedRecords);
    void MergeSamePermission(const PermissionUsageFlag& flag, const PermissionUsedRecord& inRecord,
        PermissionUsedRecord& outRecord);
    void FillPermissionUsedRecords(const PermissionUsedRecord& record, const PermissionUsageFlag& flag,
        std::vector<PermissionUsedRecord>& permissionRecords);
    bool FillBundleUsedRecord(const GenericValues& value, const PermissionUsageFlag& flag,
        std::map<int32_t, BundleUsedRecord>& tokenIdToBundleMap, std::map<int32_t, int32_t>& tokenIdToCountMap,
        PermissionUsedResult& result);
    bool GetRecordsFromLocalDB(const PermissionUsedRequest& request, PermissionUsedResult& result);

    void ExecuteAndUpdateRecord(uint32_t tokenId, int32_t pid, ActiveChangeType status);

#ifndef APP_SECURITY_PRIVACY_SERVICE
    void ExecuteAndUpdateRecordByPerm(const std::string& permissionName, bool switchStatus);
    bool ShowGlobalDialog(const std::string& permissionName);
#endif
    int32_t RemoveRecordFromStartList(AccessTokenID tokenId, int32_t pid, const std::string& permissionName);
    int32_t AddRecordToStartList(uint32_t tokenId, int32_t pid, const std::string& permissionName, int32_t status,
        PermissionUsedType type = PermissionUsedType::NORMAL_TYPE);

    void PermListToString(const std::vector<std::string>& permList);
    bool GetGlobalSwitchStatus(const std::string& permissionName);
    void ModifyMuteStatus(const std::string& permissionName, int32_t index, bool isMute);
    bool GetMuteStatus(const std::string& permissionName, int32_t index);

    void ExecuteCameraCallbackAsync(AccessTokenID tokenId, int32_t pid);

    void TransformEnumToBitValue(const PermissionUsedType type, uint32_t& value);
    bool AddOrUpdateUsedTypeIfNeeded(const AccessTokenID tokenId, const int32_t opCode,
        const PermissionUsedType type);
    void AddDataValueToResults(const GenericValues value, std::vector<PermissionUsedTypeInfo>& results);

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    bool HasUsingCamera();
    void ClearWindowShowing();
#endif
    bool IsCameraWindowShow(AccessTokenID tokenId);
    uint64_t GetUniqueId(uint32_t tokenId, int32_t pid) const;
    bool IsPidValid(int32_t pid) const;
    bool RegisterWindowCallback();
    void InitializeMuteState(const std::string& permissionName);
    int32_t GetAppStatus(AccessTokenID tokenId);

    bool RegisterAppStatusListener();
    bool Register();
    bool RegisterApplicationStateObserver();
    void Unregister();
    bool GetMuteParameter(const char* key, bool& isMute);

    void SetDefaultConfigValue();
    void GetConfigValue();

private:
    bool hasInited_ = false;
    OHOS::Utils::RWLock rwLock_;
    std::mutex startRecordListMutex_;
    std::vector<ContinusPermissionRecord> startRecordList_;
    SafeMap<uint64_t, sptr<IRemoteObject>> cameraCallbackMap_;

    // microphone
    std::mutex micMuteMutex_;
    std::mutex micLoadMutex_;
    bool isMicEdmMute_ = false;
    bool isMicMixMute_ = false;
    bool isMicLoad_ = false;

    // camera
    std::mutex camMuteMutex_;
    std::mutex camLoadMutex_;
    bool isCamEdmMute_ = false;
    bool isCamMixMute_ = false;
    bool isCamLoad_ = false;

    // appState
    std::mutex appStateMutex_;
    sptr<PrivacyAppStateObserver> appStateCallback_ = nullptr;

    // app manager death
    std::mutex appManagerDeathMutex_;
    std::shared_ptr<PrivacyAppManagerDeathCallback> appManagerDeathCallback_ = nullptr;

    // lockScreenState
    std::mutex lockScreenStateMutex_;
    int32_t lockScreenStatus_ = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED;

    // foreground reminder
    std::mutex foreReminderMutex_;
    std::vector<uint32_t> foreTokenIdList_;

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    std::mutex windowMutex_;
    bool isWmRegistered = false;
    sptr<PrivacyWindowManagerAgent> floatWindowCallback_ = nullptr;
    sptr<PrivacyWindowManagerAgent> pipWindowCallback_ = nullptr;

    std::mutex windowStatusMutex_;
    // camera float window
    bool camFloatWindowShowing_ = false;
    AccessTokenID floatWindowTokenId_ = 0;

    // pip window
    bool pipWindowShowing_ = false;
    AccessTokenID pipWindowTokenId_ = 0;
#endif

    // record config
    int32_t recordSizeMaximum_ = 0;
    int32_t recordAgingTime_ = 0;
#ifndef APP_SECURITY_PRIVACY_SERVICE
    std::string globalDialogBundleName_;
    std::string globalDialogAbilityName_;
    std::mutex abilityManagerMutex_;
    std::shared_ptr<LibraryLoader> abilityManagerLoader_;
#endif
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventRunner> deleteEventRunner_;
    std::shared_ptr<AccessEventHandler> deleteEventHandler_;
#endif
    std::atomic_int32_t deleteTaskNum_ = 0;

    std::mutex permUsedRecMutex_;
    std::vector<PermissionRecordCache> permUsedRecList_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_MANAGER_H