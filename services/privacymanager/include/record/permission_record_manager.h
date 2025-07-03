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

#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "access_token.h"
#include "active_change_response_info.h"
#include "add_perm_param_info.h"
#include "app_manager_death_callback.h"
#include "app_status_change_callback.h"
#include "hap_token_info.h"
#include "libraryloader.h"
#include "nocopyable.h"
#include "on_permission_used_record_callback.h"
#include "permission_record.h"
#include "permission_record_set.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "permission_used_type_info.h"
#include "privacy_param.h"
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
    bool IsUserIdValid(int32_t userID) const;
    int32_t SetPermissionUsedRecordToggleStatus(int32_t userID, bool status);
    int32_t GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status);
    void RemoveHistoryPermissionUsedRecords(std::unordered_set<AccessTokenID> tokenIDList);
    int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int32_t GetPermissionUsedRecordsAsync(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    int32_t StartUsingPermission(const PermissionUsedTypeInfo &info, int32_t callerPid);
    int32_t StartUsingPermission(const PermissionUsedTypeInfo &info, const sptr<IRemoteObject>& callback,
        int32_t callerPid);
    int32_t StopUsingPermission(AccessTokenID tokenId, int32_t pid, const std::string& permissionName,
        int32_t callerPid);
    bool HasCallerInStartList(int32_t callerPid);
    int32_t RegisterPermActiveStatusCallback(
        AccessTokenID regiterTokenId, const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback);
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback);

    void CallbackExecute(const ContinusPermissionRecord& record, const std::string& permissionName,
        PermissionUsedType type = PermissionUsedType::NORMAL_TYPE);
    int32_t PermissionListFilter(const std::vector<std::string>& listSrc, std::vector<std::string>& listRes);
    bool IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName, int32_t pid);
    int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfo>& results);
    int32_t SetMutePolicy(const PolicyType& policyType, const CallerType& callerType, bool isMute,
        AccessTokenID tokenID);
    int32_t SetEdmMutePolicy(const std::string permissionName, bool isMute);
    int32_t SetPrivacyMutePolicy(const std::string permissionName, bool isMute);
    int32_t SetTempMutePolicy(const std::string permissionName, bool isMute);
    int32_t SetHapWithFGReminder(uint32_t tokenId, bool isAllowed);

    void NotifyAppStateChange(AccessTokenID tokenId, int32_t pid, ActiveChangeType status);
    void SetLockScreenStatus(int32_t lockScreenStatus);
    int32_t GetLockScreenStatus(bool isIpc = false);

    void OnAppMgrRemoteDiedHandle();
    void OnAudioMgrRemoteDiedHandle();
    void OnCameraMgrRemoteDiedHandle();
    void RemoveRecordFromStartListByPid(const AccessTokenID tokenId, int32_t pid);
    void RemoveRecordFromStartListByToken(const AccessTokenID tokenId);
    void RemoveRecordFromStartListByOp(int32_t opCode);
    void RemoveRecordFromStartListByCallerPid(int32_t callerPid);
    void ExecuteAllCameraExecuteCallback();
    void UpdatePermRecImmediately();
    void ExecuteDeletePermissionRecordTask();

private:
    PermissionRecordManager();
    DISALLOW_COPY_AND_MOVE(PermissionRecordManager);

    bool IsAllowedUsingCamera(AccessTokenID tokenId, int32_t pid);
    bool IsAllowedUsingMicrophone(AccessTokenID tokenId, int32_t pid);

    bool CheckPermissionUsedRecordToggleStatus(int32_t userID);
    bool UpdatePermUsedRecToggleStatusMap(int32_t userID, bool status);
    void UpdatePermUsedRecToggleStatusMapFromDb();
    bool AddOrUpdateUsedStatusIfNeeded(int32_t userID, bool status);
    void AddRecToCacheAndValueVec(const PermissionRecord& record, std::vector<GenericValues>& values);
    int32_t MergeOrInsertRecord(const PermissionRecord& record);
    bool UpdatePermissionUsedRecordToDb(const PermissionRecord& record);
    int32_t AddRecord(const PermissionRecord& record);
    int32_t GetPermissionRecord(const AddPermParamInfo& info, PermissionRecord& record);
    bool CreateBundleUsedRecord(const AccessTokenID tokenId, BundleUsedRecord& bundleRecord);
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
    int32_t RemoveRecordFromStartList(AccessTokenID tokenId, int32_t pid,
        const std::string& permissionName, int32_t callerPid);
    int32_t AddRecordToStartList(const PermissionUsedTypeInfo& info, int32_t status, int32_t callerPid);

    void PermListToString(const std::vector<std::string>& permList);
    bool GetGlobalSwitchStatus(const std::string& permissionName);
    void ModifyMuteStatus(const std::string& permissionName, int32_t index, bool isMute);
    bool GetMuteStatus(const std::string& permissionName, int32_t index);

    void ExecuteCameraCallbackAsync(AccessTokenID tokenId, int32_t pid);

    void TransformEnumToBitValue(const PermissionUsedType type, uint32_t& value);
    bool AddOrUpdateUsedTypeIfNeeded(const AccessTokenID tokenId, const int32_t opCode,
        const PermissionUsedType type);
    void AddDataValueToResults(const GenericValues value, std::vector<PermissionUsedTypeInfo>& results);

    bool IsCameraWindowShow(AccessTokenID tokenId);
    uint64_t GetUniqueId(uint32_t tokenId, int32_t pid) const;
    bool RegisterWindowCallback();
    void InitializeMuteState(const std::string& permissionName);
    int32_t GetAppStatus(AccessTokenID tokenId, int32_t pid = -1);

    bool RegisterAppStatusListener();
    bool Register();
    bool RegisterApplicationStateObserver();
    void Unregister();
    bool GetMuteParameter(const char* key, bool& isMute);

    void SetDefaultConfigValue();
    void GetConfigValue();
    bool ToRemoveRecord(const ContinusPermissionRecord& targetRecord,
        const IsEqualFunc& isEqualFunc, bool needClearCamera = true);

private:
    bool hasInited_ = false;
    OHOS::Utils::RWLock rwLock_;
    std::mutex startRecordListMutex_;
    std::set<ContinusPermissionRecord> startRecordList_;
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

    // record config
    int32_t recordSizeMaximum_ = 0;
    int32_t recordAgingTime_ = 0;
#ifndef APP_SECURITY_PRIVACY_SERVICE
    std::string globalDialogBundleName_;
    std::string globalDialogAbilityName_;
    std::mutex abilityManagerMutex_;
    std::shared_ptr<LibraryLoader> abilityManagerLoader_;
#endif
    std::atomic_int32_t deleteTaskNum_ = 0;

    std::mutex permUsedRecMutex_;
    std::vector<PermissionRecordCache> permUsedRecList_;

    std::mutex permUsedRecToggleStatusMutex_;
    std::map<int32_t, bool> permUsedRecToggleStatusMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_MANAGER_H