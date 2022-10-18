/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sensitive_resource_manager.h"
#include <semaphore.h>
#include "ability_manager_client.h"
#include "accesstoken_log.h"
#include "active_change_response_info.h"
#include "audio_system_manager.h"
#include "iservice_registry.h"
#include "privacy_error.h"
#include "system_ability_definition.h"
#include "window_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "SensitiveResourceManager"
};
static const size_t MAX_CALLBACK_SIZE = 200;
}

using namespace OHOS::Rosen;
using namespace OHOS::AudioStandard;

static const std::string PERMISSION_MANAGER_BUNDLE_NAME = "com.ohos.permissionmanager";
static const std::string PERMISSION_MANAGER_DIALOG_ABILITY = "com.ohos.permissionmanager.GlobalExtAbility";
static const std::string RESOURCE_KEY = "ohos.sensitive.resource";

SensitiveResourceManager& SensitiveResourceManager::GetInstance()
{
    static SensitiveResourceManager instance;
    return instance;
}

SensitiveResourceManager::SensitiveResourceManager()
{
}

SensitiveResourceManager::~SensitiveResourceManager()
{
}

bool SensitiveResourceManager::InitProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return false;
    }

    sptr<IRemoteObject> object = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (object == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "GetSystemAbility %{public}d is null", APP_MGR_SERVICE_ID);
        return false;
    }

    appMgrProxy_ = iface_cast<AppExecFwk::IAppMgr>(object);
    if (appMgrProxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
        return false;
    }

    return true;
}

OHOS::sptr<OHOS::AppExecFwk::IAppMgr> SensitiveResourceManager::GetAppManagerProxy()
{
    if (appMgrProxy_ == nullptr) {
        if (!InitProxy()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "InitProxy failed");
            return nullptr;
        }
    }

    return appMgrProxy_;
}

bool SensitiveResourceManager::GetAppStatus(const std::string& pkgName, int32_t& status)
{
    auto appMgrProxy = GetAppManagerProxy();
    if (appMgrProxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetAppManagerProxy failed");
        return false;
    }

    std::vector<AppExecFwk::AppStateData> foreGroundAppList;
    appMgrProxy->GetForegroundApplications(foreGroundAppList);

    status = PERM_ACTIVE_IN_BACKGROUND;
    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [pkgName](const auto& foreGroundApp) { return foreGroundApp.bundleName == pkgName; })) {
        status = PERM_ACTIVE_IN_FOREGROUND;
    }
    return true;
}

bool SensitiveResourceManager::GetGlobalSwitch(const ResourceType type)
{
    if (type == MICROPHONE) {
        return !(AudioSystemManager::GetInstance()->IsMicrophoneMute());
    }

    return true;
}

bool SensitiveResourceManager::IsFlowWindowShow(AccessTokenID tokenId)
{
    std::lock_guard<std::mutex> lock(flowWindowMutex_);
    if (tokenId != flowWindowId_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}d is not FlowWindowStatusId, currId: %{public}d", tokenId, flowWindowId_);
        return false;
    }

    return flowWindowStatus_;
}

void SensitiveResourceManager::SetFlowWindowStatus(AccessTokenID tokenId, bool isShow)
{
    std::lock_guard<std::mutex> lock(flowWindowMutex_);
    flowWindowId_ = tokenId;
    flowWindowStatus_ = isShow;
}

int32_t SensitiveResourceManager::ShowDialog(const ResourceType& type)
{
    AAFwk::Want want;
    want.SetElementName(PERMISSION_MANAGER_BUNDLE_NAME, PERMISSION_MANAGER_DIALOG_ABILITY);
    std::string typeStr = "";
    switch (type) {
        case ResourceType::CAMERA:
            typeStr = "camera";
            break;
        case ResourceType::MICROPHONE:
            typeStr = "microphone";
            break;
        default:
            ACCESSTOKEN_LOG_ERROR(LABEL, "type is invalid, type:%{public}d", type);
            return ERR_PARAM_INVALID;
    }
    want.SetParam(RESOURCE_KEY, typeStr);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, nullptr);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to StartAbility, err:%{public}d", err);
        return ERR_SERVICE_ABNORMAL;
    }
    return RET_SUCCESS;
}

int32_t SensitiveResourceManager::RegisterAppStatusChangeCallback(uint32_t tokenId, OnAppStatusChangeCallback callback)
{
    if (tokenId == 0 || callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId or callback is invalid.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    
    std::lock_guard<std::mutex> lock(appStatusMutex_);
    auto iter = std::find_if(appStateCallbacks_.begin(), appStateCallbacks_.end(),
        [callback](const sptr<ApplicationStatusChangeCallback>& rec) {
        return callback == rec->GetCallback();
    });
    if (iter != appStateCallbacks_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "callback is already registered, add TokenId(%{public}d).", tokenId);
        (*iter)->AddTokenId(tokenId);
        return RET_SUCCESS;
    }

    if (appStateCallbacks_.size() >= MAX_CALLBACK_SIZE) {
        ACCESSTOKEN_LOG_INFO(LABEL, "callback counts reach the max.");
        return PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }

    sptr<ApplicationStatusChangeCallback> listener = new (std::nothrow) ApplicationStatusChangeCallback();
    if (listener == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new fail.");
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    listener->SetCallback(callback);
    listener->AddTokenId(tokenId);

    auto appMgrProxy = GetAppManagerProxy();
    if (appMgrProxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetAppManagerProxy failed");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    appStateCallbacks_.emplace_back(listener);
    appMgrProxy->RegisterApplicationStateObserver(listener);

    ACCESSTOKEN_LOG_DEBUG(LABEL, "register callback(%{public}p),  add TokenId(%{public}d).", callback, tokenId);

    return RET_SUCCESS;
}

int32_t SensitiveResourceManager::UnRegisterAppStatusChangeCallback(
    uint32_t tokenId, OnAppStatusChangeCallback callback)
{
    if (tokenId == 0 || callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId or callback is invalid.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    
    std::lock_guard<std::mutex> lock(appStatusMutex_);
    auto iter = std::find_if(appStateCallbacks_.begin(), appStateCallbacks_.end(),
        [callback](const sptr<ApplicationStatusChangeCallback>& rec) {
        return callback == rec->GetCallback();
    });
    if (iter == appStateCallbacks_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is not found.");
        return PrivacyError::ERR_CALLBACK_NOT_EXIST;
    }

    auto appMgrProxy = GetAppManagerProxy();
    if (appMgrProxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetAppManagerProxy failed");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    (*iter)->RemoveTokenId(tokenId);
    if (!(*iter)->IsHasListener()) {
        appMgrProxy->UnregisterApplicationStateObserver(*iter);
        appStateCallbacks_.erase(iter);
    }
    
    ACCESSTOKEN_LOG_DEBUG(LABEL, "unregister callback(%{public}p).", callback);

    return RET_SUCCESS;
}

int32_t SensitiveResourceManager::RegisterMicGlobalSwitchChangeCallback(OnMicGlobalSwitchChangeCallback callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback could not be null.");
        return ERR_CALLBACK_NOT_EXIST;
    }
    
    std::lock_guard<std::mutex> lock(micGlobalSwitchMutex_);
    auto iter = std::find_if(micGlobalSwitchCallbacks_.begin(), micGlobalSwitchCallbacks_.end(),
        [callback](const std::shared_ptr<MicGlobalSwitchChangeCallback>& rec) {
        return callback == rec->GetCallback();
    });
    if (iter != micGlobalSwitchCallbacks_.end()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "callback is already registered");
        return ERR_CALLBACK_ALREADY_EXIST;
    }

    std::shared_ptr<MicGlobalSwitchChangeCallback> listener = std::make_shared<MicGlobalSwitchChangeCallback>(
        MicGlobalSwitchChangeCallback());
    if (listener == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new fail.");
        return ERR_MALLOC_FAILED;
    }
    listener->SetCallback(callback);
    micGlobalSwitchCallbacks_.emplace_back(listener);

    AudioStandard::AudioRoutingManager::GetInstance()->SetMicStateChangeCallback(listener);
    ACCESSTOKEN_LOG_INFO(LABEL, "register Microphone callback(%{public}p).", callback);

    return RET_SUCCESS;
}

int32_t SensitiveResourceManager::UnRegisterMicGlobalSwitchChangeCallback(OnMicGlobalSwitchChangeCallback callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback could not be null.");
        return ERR_CALLBACK_NOT_EXIST;
    }

    std::lock_guard<std::mutex> lock(micGlobalSwitchMutex_);
    auto iter = std::find_if(micGlobalSwitchCallbacks_.begin(), micGlobalSwitchCallbacks_.end(),
        [callback](const std::shared_ptr<MicGlobalSwitchChangeCallback>& res) {
        return callback == res->GetCallback();
    });
    if (iter == micGlobalSwitchCallbacks_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is not found.");
        return ERR_CALLBACK_NOT_EXIST;
    }

    micGlobalSwitchCallbacks_.erase(iter);
    ACCESSTOKEN_LOG_INFO(LABEL, "unregister callback(%{public}p).", callback);
    return RET_SUCCESS;
}

int32_t SensitiveResourceManager::RegisterCameraFloatWindowChangeCallback(OnCameraFloatWindowChangeCallback callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback could not be null.");
        return ERR_CALLBACK_NOT_EXIST;
    }
    
    std::lock_guard<std::mutex> lock(cameraFloatWindowMutex_);
    auto iter = std::find_if(cameraFloatWindowCallbacks_.begin(), cameraFloatWindowCallbacks_.end(),
        [callback](const sptr<CameraFloatWindowChangeCallback>& rec) {
        return callback == rec->GetCallback();
    });
    if (iter != cameraFloatWindowCallbacks_.end()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "callback is already registered");
        return ERR_CALLBACK_ALREADY_EXIST;
    }

    sptr<CameraFloatWindowChangeCallback> listener = new (std::nothrow) CameraFloatWindowChangeCallback();
    if (listener == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new fail.");
        return ERR_MALLOC_FAILED;
    }
    listener->SetCallback(callback);

    cameraFloatWindowCallbacks_.emplace_back(listener);
    Rosen::WindowManager::GetInstance().RegisterCameraFloatWindowChangedListener(listener);

    ACCESSTOKEN_LOG_INFO(LABEL, "register callback(%{public}p).", callback);

    return RET_SUCCESS;
}

int32_t SensitiveResourceManager::UnRegisterCameraFloatWindowChangeCallback(OnCameraFloatWindowChangeCallback callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback could not be null.");
        return ERR_CALLBACK_NOT_EXIST;
    }
    
    std::lock_guard<std::mutex> lock(cameraFloatWindowMutex_);
    auto iter = std::find_if(cameraFloatWindowCallbacks_.begin(), cameraFloatWindowCallbacks_.end(),
        [callback](const sptr<CameraFloatWindowChangeCallback>& rec) {
        return callback == rec->GetCallback();
    });
    if (iter == cameraFloatWindowCallbacks_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is not found.");
        return ERR_CALLBACK_NOT_EXIST;
    }

    WindowManager::GetInstance().UnregisterCameraFloatWindowChangedListener(*iter);
    cameraFloatWindowCallbacks_.erase(iter);

    ACCESSTOKEN_LOG_INFO(LABEL, "unregister callback(%{public}p).", callback);

    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
