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

#include "access_token.h"
#include "active_change_response_info.h"
#include "add_perm_param_info.h"
#include "app_manager_death_callback.h"
#include "app_manager_death_recipient.h"
#include "app_status_change_callback.h"
#include "audio_global_switch_change_stub.h"
#include "camera_service_callback_stub.h"
#include "hap_token_info.h"
#include "libraryloader.h"
#include "nocopyable.h"
#include "on_permission_used_record_callback.h"
#include "permission_record.h"
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
    void OnApplicationStateChanged(const AppStateData &appStateData) override;
    void OnForegroundApplicationChanged(const AppStateData &appStateData) override;
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
    void RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& deviceID);
    int32_t GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int32_t GetPermissionUsedRecordsAsync(
        const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    int32_t StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName);
    int32_t StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
        const sptr<IRemoteObject>& callback);
    int32_t StopUsingPermission(AccessTokenID tokenId, const std::string& permissionName);
    int32_t RegisterPermActiveStatusCallback(
        const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback);
    int32_t UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback);

    void CallbackExecute(AccessTokenID tokenId, const std::string& permissionName, int32_t status);
    int32_t PermissionListFilter(const std::vector<std::string>& listSrc, std::vector<std::string>& listRes);
    bool IsAllowedUsingPermission(AccessTokenID tokenId, const std::string& permissionName);
    int32_t GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
        std::vector<PermissionUsedTypeInfo>& results);
    int32_t SetMutePolicy(const PolicyType& policyType, const CallerType& callerType, bool isMute);
    int32_t SetEdmMutePolicy(const std::string permissionName, bool& isMute);
    int32_t SetPrivacyMutePolicy(const std::string permissionName, bool& isMute);
    int32_t SetTempMutePolicy(const std::string permissionName, bool& isMute);

    void NotifyMicChange(bool isMute);
    void NotifyCameraChange(bool isMute);
    void NotifyAppStateChange(AccessTokenID tokenId, ActiveChangeType status);
    void SetLockScreenStatus(int32_t lockScreenStatus);
    int32_t GetLockScreenStatus();
    bool IsScreenOn();

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    void NotifyCameraWindowChange(bool isPip, AccessTokenID tokenId, bool isShowing);
    void OnWindowMgrRemoteDied();
#endif
    void OnAppMgrRemoteDiedHandle();
    void OnAudioMgrRemoteDiedHandle();
    void OnCameraMgrRemoteDiedHandle();
    void RemoveRecordFromStartListByToken(const AccessTokenID tokenId);
    void RemoveRecordFromStartListByOp(int32_t opCode);
    void ExecuteAllCameraExecuteCallback();

private:
    PermissionRecordManager();
    DISALLOW_COPY_AND_MOVE(PermissionRecordManager);

    bool IsAllowedUsingCamera(AccessTokenID tokenId);
    bool IsAllowedUsingMicrophone(AccessTokenID tokenId);

    void GetLocalRecordTokenIdList(std::set<AccessTokenID>& tokenIdList);
    void AddRecord(const PermissionRecord& record);
    int32_t GetPermissionRecord(const AddPermParamInfo& info, PermissionRecord& record);
    bool CreateBundleUsedRecord(const AccessTokenID tokenId, BundleUsedRecord& bundleRecord);
    void ExecuteDeletePermissionRecordTask();
    int32_t DeletePermissionRecord(int32_t days);
    bool GetRecordsFromLocalDB(const PermissionUsedRequest& request, PermissionUsedResult& result);
    void GetRecords(int32_t flag, std::vector<GenericValues> recordValues,
        BundleUsedRecord& bundleRecord, PermissionUsedResult& result);
    void UpdateRecords(int32_t flag, const PermissionUsedRecord& inBundleRecord, PermissionUsedRecord& outBundleRecord);

    void ExecuteAndUpdateRecord(uint32_t tokenId, ActiveChangeType status);
    void ExecuteAndUpdateRecordByPerm(const std::string& permissionName, bool switchStatus);
    void RemoveRecordFromStartList(const PermissionRecord& record);
    bool GetRecordFromStartList(uint32_t tokenId,  int32_t opCode, PermissionRecord& record);
    bool AddRecordToStartList(const PermissionRecord& record);

    std::string GetDeviceId(AccessTokenID tokenId);
    void PermListToString(const std::vector<std::string>& permList);
    bool GetGlobalSwitchStatus(const std::string& permissionName);
    bool ShowGlobalDialog(const std::string& permissionName);
    void ModifyMuteStatus(const std::string& permissionName, int32_t index, bool isMute);
    bool GetMuteStatus(const std::string& permissionName, int32_t index);

    void ExecuteCameraCallbackAsync(AccessTokenID tokenId);

    void TransformEnumToBitValue(const PermissionUsedType type, uint32_t& value);
    bool AddOrUpdateUsedTypeIfNeeded(const AccessTokenID tokenId, const int32_t opCode,
        const PermissionUsedType type);
    void RemovePermissionUsedType(AccessTokenID tokenId);
    void AddDataValueToResults(const GenericValues value, std::vector<PermissionUsedTypeInfo>& results);

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    bool HasUsingCamera();
    void ClearWindowShowing();
#endif
    bool IsCameraWindowShow(AccessTokenID tokenId);
    bool RegisterWindowCallback();
    bool UnRegisterWindowCallback();
    int32_t GetAppStatus(AccessTokenID tokenId);

    bool RegisterAppStatusListener();
    bool Register();
    bool RegisterApplicationStateObserver();
    void Unregister();
    bool GetMuteParameter(const char* key, bool& isMute);

    void SetDefaultConfigValue();
    void GetConfigValue();

private:
    OHOS::ThreadPool deleteTaskWorker_;
    bool hasInited_;
    OHOS::Utils::RWLock rwLock_;
    std::mutex startRecordListMutex_;
    std::vector<PermissionRecord> startRecordList_;
    SafeMap<AccessTokenID, sptr<IRemoteObject>> cameraCallbackMap_;

    // microphone
    std::mutex micMuteMutex_;
    std::mutex micCallbackMutex_;
    bool isMicEdmMute_ = false;
    bool isMicMixMute_ = false;
    sptr<AudioRoutingManagerListenerStub> micMuteCallback_ = nullptr;

    // camera
    std::mutex camMuteMutex_;
    std::mutex cameraCallbackMutex_;
    bool isCamEdmMute_ = false;
    bool isCamMixMute_ = false;
    sptr<CameraServiceCallbackStub> camMuteCallback_ = nullptr;

    // appState
    std::mutex appStateMutex_;
    sptr<PrivacyAppStateObserver> appStateCallback_ = nullptr;

    // app manager death
    std::mutex appManagerDeathMutex_;
    std::shared_ptr<PrivacyAppManagerDeathCallback> appManagerDeathCallback_ = nullptr;

    // lockScreenState
    std::mutex lockScreenStateMutex_;
    int32_t lockScreenStatus_ = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED;

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    bool isAutoClose = false;
    std::mutex windowLoaderMutex_;
    bool isWmRegistered = false;
    LibraryLoader* windowLoader_ = nullptr;

    std::mutex windowStausMutex_;
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
    std::string globalDialogBundleName_;
    std::string globalDialogAbilityName_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_MANAGER_H