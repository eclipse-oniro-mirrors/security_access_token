/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "el5_filekey_manager_service.h"

#include <dlfcn.h>

#ifdef COMMON_EVENT_SERVICE_ENABLE
#include "common_event_manager.h"
#include "common_event_support.h"
#endif
#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_log.h"
#include "el5_memory_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#ifdef THEME_SCREENLOCK_MGR_ENABLE
#include "screenlock_manager.h"
#endif
#include "system_ability_definition.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::string PROTECT_DATA_PERMISSION = "ohos.permission.PROTECT_SCREEN_LOCK_DATA";
const std::string MEDIA_DATA_PERMISSION = "ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA";
const std::string ALL_DATA_PERMISSION = "ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA";
const std::string TASK_ID = "el5FilekeyManagerUnload";
const std::string STORAGE_DAEMON = "storage_daemon";
const std::string FOUNDATION = "foundation";
const std::string SET_POLICY_CALLER = "com.ohos.medialibrary.medialibrarydata";
constexpr uint32_t INSTALLS_UID = 3060;
constexpr uint32_t API_DELAY_TIME = 5 * 1000; // 5s
#ifdef THEME_SCREENLOCK_MGR_ENABLE
constexpr uint32_t SCREEN_ON_DELAY_TIME = 30 * 1000; // 30s
#endif
constexpr uint32_t USERID_MASK = 200000;
typedef El5FilekeyServiceExtInterface* (*GetExtInstance)(void);
}

El5FilekeyManagerService::El5FilekeyManagerService()
    : serviceRunningState_(ServiceRunningState::STATE_NOT_START)
{
    LOG_INFO("Instance created.");
}

El5FilekeyManagerService::~El5FilekeyManagerService()
{
    if (handler_) {
        dlclose(handler_);
        handler_ = nullptr;
    }
    LOG_INFO("Instance destroyed.");
}

int32_t El5FilekeyManagerService::Init()
{
    LOG_INFO("Ready to init.");
    serviceRunningState_ = ServiceRunningState::STATE_RUNNING;

#ifdef EVENTHANDLER_ENABLE
    auto runner = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    unloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
#endif

    handler_ = dlopen("/system/lib64/libel5_filekey_manager_api.z.so", RTLD_LAZY);
    if (handler_ == nullptr) {
        LOG_ERROR("Policy not exist, just start service.");
        return EFM_SUCCESS;
    }

    GetExtInstance getExtInstance = reinterpret_cast<GetExtInstance>(dlsym(handler_, "GetExtInstance"));
    if (getExtInstance == nullptr) {
        LOG_ERROR("GetExtInstance failed.");
        return EFM_ERR_CALL_POLICY_FAILED;
    }

    service_ = getExtInstance();
    if (service_ == nullptr) {
        LOG_ERROR("Ext instance is null.");
        return EFM_ERR_CALL_POLICY_ERROR;
    }

    return EFM_SUCCESS;
}

void El5FilekeyManagerService::UnInit()
{
    LOG_INFO("UnInit start");
    if (service_) {
        service_->UnInit();
    }
}

// CallbackEnter, if "option_stub_hooks on", is called per IPC call at entrance of OnRemoteRequest
int32_t El5FilekeyManagerService::CallbackEnter(uint32_t code)
{
    El5MemoryManager::GetInstance().AddFunctionRuningNum();
    return ERR_OK;
}

// CallbackExit, if "option_stub_hooks on", is called per IPC call at exit of OnRemoteRequest
int32_t El5FilekeyManagerService::CallbackExit(uint32_t code, int32_t result)
{
    El5MemoryManager::GetInstance().DecreaseFunctionRuningNum();
    return ERR_OK;
}

void El5FilekeyManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    LOG_INFO("SaId %{public}d added", systemAbilityId);
#ifdef COMMON_EVENT_SERVICE_ENABLE
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        if (subscriber_ == nullptr) {
            EventFwk::MatchingSkills matchingSkills;
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
            EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
            subscriber_ = std::make_shared<El5FilekeyManagerSubscriber>(subscribeInfo);
            bool ret = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
            if (!ret) {
                LOG_ERROR("Subscribe common event failed.");
                subscriber_ = nullptr;
            }
        }
    }
#endif

#ifdef THEME_SCREENLOCK_MGR_ENABLE
    if (systemAbilityId == SCREENLOCK_SERVICE_ID) {
        // screen is unlocked, sa is called by USER_REMOVED, auto stop in 30s.
        if (!ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked()) {
            LOG_INFO("Init when screen is unlocked.");
            PostDelayedUnloadTask(SCREEN_ON_DELAY_TIME);
        }
    }
#endif

    if (service_ != nullptr) {
        service_->OnAddSystemAbility(systemAbilityId, deviceId);
    }
}

void El5FilekeyManagerService::PostDelayedUnloadTask(uint32_t delayedTime)
{
#ifdef EVENTHANDLER_ENABLE
    auto task = []() {
        LOG_INFO("Start to unload el5_filekey_manager.");
        auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            LOG_ERROR("GetSystemAbilityManager is null.");
            return;
        }

        El5MemoryManager::GetInstance().SetIsDelayedToUnload(true);
        int32_t ret = systemAbilityManager->UnloadSystemAbility(EL5_FILEKEY_MANAGER_SERVICE_ID);
        if (ret != ERR_OK) {
            LOG_ERROR("Unload el5_filekey_manager failed.");
            return;
        }
    };
    unloadHandler_->RemoveTask(TASK_ID);
    unloadHandler_->PostTask(task, TASK_ID, delayedTime);
#endif
}

void El5FilekeyManagerService::CancelDelayedUnloadTask()
{
#ifdef EVENTHANDLER_ENABLE
    unloadHandler_->RemoveTask(TASK_ID);
#endif
}

int32_t El5FilekeyManagerService::AcquireAccess(DataLockType type)
{
    LOG_INFO("Acquire type %{public}d.", type);
    bool isApp = true;
    int32_t ret = CheckReqLockPermission(type, isApp);
    if (ret != EFM_SUCCESS) {
        return ret;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->AcquireAccess(type, isApp);
}

int32_t El5FilekeyManagerService::ReleaseAccess(DataLockType type)
{
    LOG_INFO("Release type %{public}d.", type);
    bool isApp = true;
    int32_t ret = CheckReqLockPermission(type, isApp);
    if (ret != EFM_SUCCESS) {
        return ret;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->ReleaseAccess(type, isApp);
}

int32_t El5FilekeyManagerService::GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId)
{
    LOG_INFO("Generate app key for %{public}s.", bundleName.c_str());
    if (IPCSkeleton::GetCallingUid() != INSTALLS_UID) {
        LOG_ERROR("Generate app key permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->GenerateAppKey(uid, bundleName, keyId);
}

int32_t El5FilekeyManagerService::DeleteAppKey(const std::string& bundleName, int32_t userId)
{
    LOG_INFO("Delete %{public}d's %{public}s app key.", userId, bundleName.c_str());
    if (userId < 0) {
        LOG_ERROR("UserId is invalid!");
        return EFM_ERR_INVALID_PARAMETER;
    }
    if (IPCSkeleton::GetCallingUid() != INSTALLS_UID) {
        LOG_ERROR("Delete app key permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->DeleteAppKey(bundleName, userId);
}

int32_t El5FilekeyManagerService::GetUserAppKey(int32_t userId, bool getAllFlag, std::vector<UserAppKeyInfo> &keyInfos)
{
    LOG_INFO("Get user %{public}d app key.", userId);
    if (userId < 0) {
        LOG_ERROR("UserId is invalid!");
        return EFM_ERR_INVALID_PARAMETER;
    }
    if (!VerifyNativeCallingProcess(STORAGE_DAEMON, IPCSkeleton::GetCallingTokenID())) {
        LOG_ERROR("Get user app key permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->GetUserAppKey(userId, getAllFlag, keyInfos);
}

int32_t El5FilekeyManagerService::ChangeUserAppkeysLoadInfo(int32_t userId,
    const std::vector<AppKeyLoadInfo> &loadInfos)
{
    LOG_INFO("Change user %{public}d load infos.", userId);
    if (userId < 0) {
        LOG_ERROR("UserId is invalid!");
        return EFM_ERR_INVALID_PARAMETER;
    }
    if (!VerifyNativeCallingProcess(STORAGE_DAEMON, IPCSkeleton::GetCallingTokenID())) {
        LOG_ERROR("Change user load infos permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->ChangeUserAppkeysLoadInfo(userId, loadInfos);
}

int32_t El5FilekeyManagerService::SetFilePathPolicy()
{
    int32_t userId = IPCSkeleton::GetCallingUid() / USERID_MASK;
    LOG_INFO("Set user %{public}d file path policy.", userId);
    if (!VerifyHapCallingProcess(userId, SET_POLICY_CALLER, IPCSkeleton::GetCallingTokenID())) {
        LOG_ERROR("Set file path policy permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->SetFilePathPolicy(userId);
}

int32_t El5FilekeyManagerService::RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback)
{
    LOG_INFO("Register callback.");
    if (!VerifyNativeCallingProcess(FOUNDATION, IPCSkeleton::GetCallingTokenID())) {
        LOG_ERROR("Register callback permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->RegisterCallback(callback);
}

int32_t El5FilekeyManagerService::GenerateGroupIDKey(uint32_t uid, const std::string &groupID, std::string &keyId)
{
    LOG_INFO("Generate groupID for %{public}s.", groupID.c_str());
    if (IPCSkeleton::GetCallingUid() != INSTALLS_UID) {
        LOG_ERROR("Generate groupID permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->GenerateGroupIDKey(uid, groupID, keyId);
}

int32_t El5FilekeyManagerService::DeleteGroupIDKey(uint32_t uid, const std::string &groupID)
{
    LOG_INFO("Delete %{public}d's %{public}s app key.", uid, groupID.c_str());
    if (IPCSkeleton::GetCallingUid() != INSTALLS_UID) {
        LOG_ERROR("Delete app key permission denied.");
        return EFM_ERR_NO_PERMISSION;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->DeleteGroupIDKey(uid, groupID);
}

int32_t El5FilekeyManagerService::QueryAppKeyState(DataLockType type)
{
    LOG_INFO("Query type %{public}d.", type);
    bool isApp = true;
    int32_t ret = CheckReqLockPermission(type, isApp);
    if (ret != EFM_SUCCESS) {
        return ret;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }

    return service_->QueryAppKeyState(type, isApp);
}

bool El5FilekeyManagerService::IsSystemApp()
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

int32_t El5FilekeyManagerService::CheckReqLockPermission(DataLockType type, bool& isApp)
{
    int32_t ret = EFM_ERR_NO_PERMISSION;
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    isApp = AccessTokenKit::GetTokenType(callingTokenID) == ATokenTypeEnum::TOKEN_HAP;
    switch (type) {
        case DataLockType::DEFAULT_DATA:
            if (!isApp || (AccessTokenKit::VerifyAccessToken(callingTokenID, PROTECT_DATA_PERMISSION) !=
                PermissionState::PERMISSION_GRANTED)) {
                LOG_ERROR("Data protection is not enabled.");
                ret = EFM_ERR_FIND_ACCESS_FAILED;
            } else {
                ret = EFM_SUCCESS;
            }
            break;
        case DataLockType::MEDIA_DATA:
            if (isApp && !IsSystemApp()) {
                ret = EFM_ERR_NOT_SYSTEM_APP;
                LOG_ERROR("Not system app.");
            } else {
                if (AccessTokenKit::VerifyAccessToken(callingTokenID, MEDIA_DATA_PERMISSION) !=
                    PermissionState::PERMISSION_GRANTED) {
                    LOG_ERROR("Acquire or release type %{public}d permission denied.", type);
                } else {
                    ret = EFM_SUCCESS;
                }
            }
            break;
        case DataLockType::ALL_DATA:
            if (isApp && !IsSystemApp()) {
                ret = EFM_ERR_NOT_SYSTEM_APP;
                LOG_ERROR("Not system app.");
            } else {
                if (AccessTokenKit::VerifyAccessToken(callingTokenID, ALL_DATA_PERMISSION) !=
                    PermissionState::PERMISSION_GRANTED) {
                    LOG_ERROR("Acquire or release type %{public}d permission denied.", type);
                } else {
                    ret = EFM_SUCCESS;
                }
            }
            break;
        default:
            break;
    }
    return ret;
}

bool El5FilekeyManagerService::VerifyNativeCallingProcess(const std::string &validCaller,
    const AccessTokenID &callerTokenId)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId(validCaller);
    return tokenId == callerTokenId;
}

bool El5FilekeyManagerService::VerifyHapCallingProcess(int32_t userId, const std::string &validCaller,
    const AccessTokenID &callerTokenId)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(userId, validCaller, 0);
    return tokenId == callerTokenId;
}

int32_t El5FilekeyManagerService::SetPolicyScreenLocked()
{
    LOG_INFO("Service SetPolicyScreenLocked");
    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }
    return service_->SetPolicyScreenLocked();
}

int32_t El5FilekeyManagerService::HandleUserCommonEvent(const std::string &eventName, int32_t userId)
{
    LOG_INFO("Service handle event:%{public}s userId:%{public}d", eventName.c_str(), userId);
    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }
    return service_->HandleUserCommonEvent(eventName, userId);
}

int El5FilekeyManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    LOG_INFO("El5FilekeyManager Dump");
    if (fd < 0) {
        return EFM_ERR_INVALID_PARAMETER;
    }

    dprintf(fd, "El5FilekeyManager Dump:\n");
    std::string arg0 = ((args.size() == 0) ? "" : Str16ToStr8(args.at(0)));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "       -h: command help\n");
        dprintf(fd, "       -a: dump all el5 data information \n");
        dprintf(fd, "       -t [time]: use arguments time to set screen lock timeout minutes only in deleloper mode\n");
        return EFM_SUCCESS;
    }

    if (service_ == nullptr) {
        LOG_ERROR("Failed to get policy.");
        PostDelayedUnloadTask(API_DELAY_TIME);
        return EFM_SUCCESS;
    }
    LOG_INFO("Start dump data");
    service_->DumpData(fd, args);

    return EFM_SUCCESS;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
