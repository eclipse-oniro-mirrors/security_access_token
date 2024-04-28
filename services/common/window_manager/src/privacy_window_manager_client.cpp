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
#include "privacy_window_manager_client.h"

#include <thread>
#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "privacy_error.h"

#include "privacy_mock_session_manager_proxy.h"
#include "privacy_scene_session_manager_proxy.h"
#include "privacy_scene_session_manager_lite_proxy.h"
#include "privacy_session_manager_proxy.h"
#include "privacy_window_manager_proxy.h"
#include "scene_board_judgement.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyWindowManagerClient"
};
std::recursive_mutex g_instanceMutex;
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length
} // namespace

PrivacyWindowManagerClient& PrivacyWindowManagerClient::GetInstance()
{
    static PrivacyWindowManagerClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PrivacyWindowManagerClient();
        }
    }
    return *instance;
}

PrivacyWindowManagerClient::PrivacyWindowManagerClient()
{}

PrivacyWindowManagerClient::~PrivacyWindowManagerClient()
{}

int32_t PrivacyWindowManagerClient::RegisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    if (type == WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW) {
        return RegisterWindowManagerAgentLite(type, windowManagerAgent);
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERR_SERVICE_ABNORMAL;
    }
    return proxy->RegisterWindowManagerAgent(type, windowManagerAgent);
}

int32_t PrivacyWindowManagerClient::UnregisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    if (type == WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW) {
        return UnregisterWindowManagerAgentLite(type, windowManagerAgent);
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERR_SERVICE_ABNORMAL;
    }
    return proxy->UnregisterWindowManagerAgent(type, windowManagerAgent);
}

int32_t PrivacyWindowManagerClient::RegisterWindowManagerAgentLite(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    auto proxy = GetLiteProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERR_SERVICE_ABNORMAL;
    }
    return proxy->RegisterWindowManagerAgent(type, windowManagerAgent);
}

int32_t PrivacyWindowManagerClient::UnregisterWindowManagerAgentLite(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    auto proxy = GetLiteProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERR_SERVICE_ABNORMAL;
    }
    return proxy->UnregisterWindowManagerAgent(type, windowManagerAgent);
}

void PrivacyWindowManagerClient::AddDeathCallback(void (*callback)())
{
    std::lock_guard<std::mutex> lock(deathMutex_);
    deathCallback_ = callback;
}

void PrivacyWindowManagerClient::InitSessionManagerServiceProxy()
{
    if (sessionManagerServiceProxy_) {
        return;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to get system ability mgr.");
        return;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (!remoteObject) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote object is nullptr");
        return;
    }
    mockSessionManagerServiceProxy_ = iface_cast<IMockSessionManagerInterface>(remoteObject);
    if (!mockSessionManagerServiceProxy_) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Get mock session manager service proxy failed, nullptr");
        return;
    }
    sptr<IRemoteObject> remoteObject2 = mockSessionManagerServiceProxy_->GetSessionManagerService();
    if (!remoteObject2) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote object2 is nullptr");
        return;
    }
    sessionManagerServiceProxy_ = iface_cast<ISessionManagerService>(remoteObject2);
    if (!sessionManagerServiceProxy_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "sessionManagerServiceProxy_ is nullptr");
    }
}

void PrivacyWindowManagerClient::InitSceneSessionManagerProxy()
{
    if (sceneSessionManagerProxy_) {
        return;
    }
    if (!sessionManagerServiceProxy_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "sessionManagerServiceProxy_ is nullptr");
        return;
    }

    sptr<IRemoteObject> remoteObject = sessionManagerServiceProxy_->GetSceneSessionManager();
    if (!remoteObject) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Get scene session manager proxy failed, scene session manager service is null");
        return;
    }
    sceneSessionManagerProxy_ = iface_cast<ISceneSessionManager>(remoteObject);
    if (sceneSessionManagerProxy_ == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "sceneSessionManagerProxy_ is null.");
        return;
    }
    serviceDeathObserver_ = new (std::nothrow) PrivacyWindowManagerDeathRecipient();
    if (!serviceDeathObserver_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create death Recipient ptr WMSDeathRecipient");
        return;
    }
    if (remoteObject->IsProxyObject() && !remoteObject->AddDeathRecipient(serviceDeathObserver_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to add death recipient");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "InitSceneSessionManagerProxy end.");
}

void PrivacyWindowManagerClient::InitSceneSessionManagerLiteProxy()
{
    if (sceneSessionManagerLiteProxy_) {
        return;
    }
    if (!sessionManagerServiceProxy_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "sessionManagerServiceProxy_ is nullptr");
        return;
    }

    sptr<IRemoteObject> remoteObject = sessionManagerServiceProxy_->GetSceneSessionManagerLite();
    if (!remoteObject) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Get scene session manager proxy failed, scene session manager service is null");
        return;
    }
    sceneSessionManagerLiteProxy_ = iface_cast<ISceneSessionManagerLite>(remoteObject);
    if (sceneSessionManagerLiteProxy_ == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "sceneSessionManagerLiteProxy_ is null.");
        return;
    }
    serviceDeathObserver_ = new (std::nothrow) PrivacyWindowManagerDeathRecipient();
    if (!serviceDeathObserver_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create death Recipient ptr WMSDeathRecipient");
        return;
    }
    if (remoteObject->IsProxyObject() && !remoteObject->AddDeathRecipient(serviceDeathObserver_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to add death recipient");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "InitSceneSessionManagerLiteProxy end.");
}

sptr<ISceneSessionManager> PrivacyWindowManagerClient::GetSSMProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    InitSessionManagerServiceProxy();
    InitSceneSessionManagerProxy();
    return sceneSessionManagerProxy_;
}

sptr<ISceneSessionManagerLite> PrivacyWindowManagerClient::GetSSMLiteProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    InitSessionManagerServiceProxy();
    InitSceneSessionManagerLiteProxy();
    return sceneSessionManagerLiteProxy_;
}

void PrivacyWindowManagerClient::InitWMSProxy()
{
    if (wmsProxy_) {
        return;
    }
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return;
    }
    auto windowManagerSa = sam->GetSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (windowManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
            WINDOW_MANAGER_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) PrivacyWindowManagerDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        windowManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    wmsProxy_ = iface_cast<IWindowManager>(windowManagerSa);
    if (wmsProxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "wmsProxy_ is null.");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "InitWMSProxy end.");
}

sptr<IWindowManager> PrivacyWindowManagerClient::GetWMSProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    InitWMSProxy();
    return wmsProxy_;
}

void PrivacyWindowManagerClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    mockSessionManagerServiceProxy_ = nullptr;
    sessionManagerServiceProxy_ = nullptr;
    sceneSessionManagerProxy_ = nullptr;
    sceneSessionManagerLiteProxy_ = nullptr;
    wmsProxy_ = nullptr;

    std::function<void()> runner = [this]() {
        std::string name = "WindowMgrDiedHandler";
        pthread_setname_np(pthread_self(), name.substr(0, MAX_PTHREAD_NAME_LEN).c_str());
        auto sleepTime = std::chrono::milliseconds(1000);
        std::this_thread::sleep_for(sleepTime);
        std::lock_guard<std::mutex> lock(deathMutex_);
        if (this->deathCallback_) {
            this->deathCallback_();
        }
    };

    std::thread initThread(runner);
    initThread.detach();
}

sptr<IWindowManagerLite> PrivacyWindowManagerClient::GetLiteProxy()
{
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return nullptr;
    }
    return GetSSMLiteProxy();
}

sptr<IWindowManager> PrivacyWindowManagerClient::GetProxy()
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return GetSSMProxy();
    }
    return GetWMSProxy();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

