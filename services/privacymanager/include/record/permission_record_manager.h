/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "nocopyable.h"
#include "on_permission_used_record_callback.h"
#include "permission_record.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "rwlock.h"
#include "thread_pool.h"
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
#include "window_manager_privacy_agent.h"
#endif
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
#include "nlohmann/json.hpp"
#include "permission_record_config.h"
#endif

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

    void NotifyMicChange(bool isMute);
    void NotifyCameraChange(bool isMute);
    void NotifyAppStateChange(AccessTokenID tokenId, ActiveChangeType status);
    void SetLockScreenStatus(int32_t lockScreenStatus);
    int32_t GetLockScreenStatus();

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    void NotifyCameraFloatWindowChange(AccessTokenID tokenId, bool isShowing);
    void OnWindowMgrRemoteDiedHandle();
#endif
    void OnAppMgrRemoteDiedHandle();
    void OnAudioMgrRemoteDiedHandle();
    void OnCameraMgrRemoteDiedHandle();
    int32_t GetRecordSizeMaxImum();
    int32_t GetRecordAgingTime();
    void RemoveRecordFromStartListByToken(const AccessTokenID tokenId);

private:
    PermissionRecordManager();
    DISALLOW_COPY_AND_MOVE(PermissionRecordManager);

    void GetLocalRecordTokenIdList(std::set<AccessTokenID>& tokenIdList);
    void AddRecord(const PermissionRecord& record);
    int32_t GetPermissionRecord(AccessTokenID tokenId, const std::string& permissionName,
        int32_t successCount, int32_t failCount, PermissionRecord& record);
    bool CreateBundleUsedRecord(const AccessTokenID tokenId, BundleUsedRecord& bundleRecord);
    void ExecuteDeletePermissionRecordTask();
    int32_t DeletePermissionRecord(int32_t days);
    bool GetRecordsFromLocalDB(const PermissionUsedRequest& request, PermissionUsedResult& result);
    void GetRecords(int32_t flag, std::vector<GenericValues> recordValues,
        BundleUsedRecord& bundleRecord, PermissionUsedResult& result);
    void UpdateRecords(int32_t flag, const PermissionUsedRecord& inBundleRecord, PermissionUsedRecord& outBundleRecord);

    void ExecuteAndUpdateRecord(uint32_t tokenId, ActiveChangeType status);
    void ExecuteAndUpdateRecord(uint32_t opCode, bool switchStatus);
    void RemoveRecordFromStartList(const PermissionRecord& record);
    void UpdateRecord(const PermissionRecord& record);
    bool GetRecordFromStartList(uint32_t tokenId,  int32_t opCode, PermissionRecord& record);
    bool AddRecordToStartList(const PermissionRecord& record);

    std::string GetDeviceId(AccessTokenID tokenId);
    void PermListToString(const std::vector<std::string>& permList);
    bool GetGlobalSwitchStatus(const std::string& permissionName);
    bool ShowGlobalDialog(const std::string& permissionName);

    void ExecuteCameraCallbackAsync(AccessTokenID tokenId);
    void SetCameraCallback(sptr<IRemoteObject>);

    void GenerateNewUsedType(const PermissionUsedType type, int32_t& dataType);
    bool AddOrUpdateUsedTypeIfNeeded(const AccessTokenID tokenId, const int32_t opCode,
        const PermissionUsedType type);
    void RemovePermissionUsedType(AccessTokenID tokenId);

#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    bool IsFlowWindowShow(AccessTokenID tokenId);
#endif
    int32_t GetAppStatus(AccessTokenID tokenId);

    bool RegisterAppStatusAndLockScreenStatusListener();
    bool Register();
    bool RegisterApplicationStateObserver();
    void Unregister();

#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
    void GetConfigFilePathList(std::vector<std::string> &pathList);
    void from_json(const nlohmann::json& j, PermissionRecordConfig& p);
    bool GetConfigValueFromFile(std::string& fileContent);
#endif
    void SetDefaultConfigValue();
    void GetConfigValue();
private:
    OHOS::ThreadPool deleteTaskWorker_;
    bool hasInited_;
    OHOS::Utils::RWLock rwLock_;
    std::mutex startRecordListMutex_;
    std::vector<PermissionRecord> startRecordList_;
    std::mutex cameraMutex_;
    std::mutex cameraCallbackMutex_;
    sptr<IRemoteObject> cameraCallback_ = nullptr;

    // microphone
    std::mutex micMuteMutex_;
    std::mutex micCallbackMutex_;
    bool isMicMute_ = false;
    sptr<AudioRoutingManagerListenerStub> micMuteCallback_ = nullptr;

    // camera
    std::mutex camMuteMutex_;
    bool isCameraMute_ = false;
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

    // camera float window
#ifdef CAMERA_FLOAT_WINDOW_ENABLE
    AccessTokenID floatWindowTokenId_ = 0;
    bool camFloatWindowShowing_ = false;
    std::mutex floatWinMutex_;
    sptr<WindowManagerPrivacyAgent> floatWindowCallback_ = nullptr;
#endif

    // record config
    int32_t recordSizeMaximum_ = 0;
    int32_t recordAgingTime_ = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_MANAGER_H