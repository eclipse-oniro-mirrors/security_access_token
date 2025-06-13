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
#include "accesstoken_common_log.h"
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
std::recursive_mutex g_instanceMutex;
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length
} // namespace

PrivacyWindowManagerClient& PrivacyWindowManagerClient::GetInstance()
{
    static PrivacyWindowManagerClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            PrivacyWindowManagerClient* tmp = new (std::nothrow) PrivacyWindowManagerClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

PrivacyWindowManagerClient::PrivacyWindowManagerClient() : deathCallback_(nullptr)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    serviceDeathObserver_ = sptr<PrivacyWindowManagerDeathRecipient>::MakeSptr();
}

PrivacyWindowManagerClient::~PrivacyWindowManagerClient()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "~PrivacyWindowManagerClient().");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    RemoveDeathRecipient();
}

int32_t PrivacyWindowManagerClient::RegisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    if (type == WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW) {
        return RegisterWindowManagerAgentLite(type, windowManagerAgent);
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null");
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
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null");
        return ERR_SERVICE_ABNORMAL;
    }
    return proxy->UnregisterWindowManagerAgent(type, windowManagerAgent);
}

int32_t PrivacyWindowManagerClient::RegisterWindowManagerAgentLite(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    auto proxy = GetLiteProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null");
        return ERR_SERVICE_ABNORMAL;
    }
    return proxy->RegisterWindowManagerAgent(type, windowManagerAgent);
}

int32_t PrivacyWindowManagerClient::UnregisterWindowManagerAgentLite(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    auto proxy = GetLiteProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null");
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
    if (sessionManagerServiceProxy_ && sessionManagerServiceProxy_->AsObject() != nullptr &&
        (!sessionManagerServiceProxy_->AsObject()->IsObjectDead())) {
        return;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to get system ability mgr.");
        return;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (!remoteObject) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Remote object is nullptr");
        return;
    }
    mockSessionManagerServiceProxy_ = new (std::nothrow) PrivacyMockSessionManagerProxy(remoteObject);
    if (!mockSessionManagerServiceProxy_  || mockSessionManagerServiceProxy_->AsObject() == nullptr ||
        mockSessionManagerServiceProxy_->AsObject()->IsObjectDead()) {
        LOGW(PRI_DOMAIN, PRI_TAG, "Get mock session manager service proxy failed, nullptr");
        return;
    }
    sptr<IRemoteObject> remoteObject2 = mockSessionManagerServiceProxy_->GetSessionManagerService();
    if (!remoteObject2) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Remote object2 is nullptr");
        return;
    }
    sessionManagerServiceProxy_ = new (std::nothrow) PrivacySessionManagerProxy(remoteObject2);
    if (!sessionManagerServiceProxy_ || sessionManagerServiceProxy_->AsObject() == nullptr ||
        sessionManagerServiceProxy_->AsObject()->IsObjectDead()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "SessionManagerServiceProxy_ is nullptr");
    }
}

void PrivacyWindowManagerClient::InitSceneSessionManagerProxy()
{
    if (sceneSessionManagerProxy_ && sceneSessionManagerProxy_->AsObject() != nullptr &&
        (!sceneSessionManagerProxy_->AsObject()->IsObjectDead())) {
        return;
    }
    if (!sessionManagerServiceProxy_ || sessionManagerServiceProxy_->AsObject() == nullptr ||
        sessionManagerServiceProxy_->AsObject()->IsObjectDead()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "SessionManagerServiceProxy_ is nullptr");
        return;
    }

    sptr<IRemoteObject> remoteObject = sessionManagerServiceProxy_->GetSceneSessionManager();
    if (!remoteObject) {
        LOGW(PRI_DOMAIN, PRI_TAG, "Get scene session manager proxy failed, scene session manager service is null");
        return;
    }
    sceneSessionManagerProxy_ = new (std::nothrow) PrivacySceneSessionManagerProxy(remoteObject);
    if (sceneSessionManagerProxy_ == nullptr || sceneSessionManagerProxy_->AsObject() == nullptr ||
        sceneSessionManagerProxy_->AsObject()->IsObjectDead()) {
        LOGW(PRI_DOMAIN, PRI_TAG, "SceneSessionManagerProxy_ is null.");
        return;
    }
    if (!serviceDeathObserver_) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to create death Recipient ptr WMSDeathRecipient");
        return;
    }
    if (remoteObject->IsProxyObject() && !remoteObject->AddDeathRecipient(serviceDeathObserver_)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to add death recipient");
        return;
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "InitSceneSessionManagerProxy end.");
}

void PrivacyWindowManagerClient::InitSceneSessionManagerLiteProxy()
{
    if (sceneSessionManagerLiteProxy_ && sceneSessionManagerLiteProxy_->AsObject() != nullptr &&
        (!sceneSessionManagerLiteProxy_->AsObject()->IsObjectDead())) {
        return;
    }
    if (!sessionManagerServiceProxy_) {
        LOGE(PRI_DOMAIN, PRI_TAG, "SessionManagerServiceProxy_ is nullptr");
        return;
    }

    sptr<IRemoteObject> remoteObject = sessionManagerServiceProxy_->GetSceneSessionManagerLite();
    if (!remoteObject) {
        LOGW(PRI_DOMAIN, PRI_TAG, "Get scene session manager proxy failed, scene session manager service is null");
        return;
    }
    sceneSessionManagerLiteProxy_ = new (std::nothrow) PrivacySceneSessionManagerLiteProxy(remoteObject);
    if (sceneSessionManagerLiteProxy_ == nullptr || sceneSessionManagerLiteProxy_->AsObject() == nullptr ||
        sceneSessionManagerLiteProxy_->AsObject()->IsObjectDead()) {
        LOGW(PRI_DOMAIN, PRI_TAG, "SceneSessionManagerLiteProxy_ is null.");
        return;
    }
    if (!serviceDeathObserver_) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to create death Recipient ptr WMSDeathRecipient");
        return;
    }
    if (remoteObject->IsProxyObject() && !remoteObject->AddDeathRecipient(serviceDeathObserver_)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to add death recipient");
        return;
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "InitSceneSessionManagerLiteProxy end.");
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
    if (wmsProxy_ && wmsProxy_->AsObject() != nullptr && (!wmsProxy_->AsObject()->IsObjectDead())) {
        return;
    }
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "GetSystemAbilityManager is null");
        return;
    }
    auto windowManagerSa = sam->GetSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (windowManagerSa == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "GetSystemAbility %{public}d is null",
            WINDOW_MANAGER_SERVICE_ID);
        return;
    }

    if (serviceDeathObserver_ != nullptr) {
        windowManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    wmsProxy_ = new (std::nothrow) PrivacyWindowManagerProxy(windowManagerSa);
    if (wmsProxy_ == nullptr  || wmsProxy_->AsObject() == nullptr || wmsProxy_->AsObject()->IsObjectDead()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "WmsProxy_ is null.");
        return;
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "InitWMSProxy end.");
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
    LOGI(PRI_DOMAIN, PRI_TAG, "Window manager remote died.");
    RemoveDeathRecipient();

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

void PrivacyWindowManagerClient::RemoveDeathRecipient()
{
    if (serviceDeathObserver_ == nullptr) {
        return;
    }
    // remove SceneSessionManager
    if (sceneSessionManagerProxy_ != nullptr) {
        sceneSessionManagerProxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    //remove SceneSessionManagerLite
    if (sceneSessionManagerLiteProxy_ != nullptr) {
        sceneSessionManagerLiteProxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    // remove WMSProxy
    if (wmsProxy_ != nullptr) {
        wmsProxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    mockSessionManagerServiceProxy_ = nullptr;
    sessionManagerServiceProxy_ = nullptr;
    sceneSessionManagerProxy_ = nullptr;
    sceneSessionManagerLiteProxy_ = nullptr;
    wmsProxy_ = nullptr;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

