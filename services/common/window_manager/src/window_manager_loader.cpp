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

#include "window_manager_loader.h"
#include "privacy_error.h"
#include "privacy_window_manager_agent.h"
#include "privacy_window_manager_client.h"
#include "scene_board_judgement.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static sptr<PrivacyWindowManagerAgent> g_floatWindowCallback = nullptr;
static sptr<PrivacyWindowManagerAgent> g_pipWindowCallback = nullptr;
}

int32_t WindowManagerLoader::RegisterFloatWindowListener(const WindowChangeCallback& callback)
{
    if (g_floatWindowCallback == nullptr) {
        g_floatWindowCallback = new (std::nothrow) PrivacyWindowManagerAgent(callback);
        if (g_floatWindowCallback == nullptr) {
            return ERR_MALLOC_FAILED;
        }
    }
    return PrivacyWindowManagerClient::GetInstance().RegisterWindowManagerAgent(
        WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, g_floatWindowCallback);
}

int32_t WindowManagerLoader::UnregisterFloatWindowListener(const WindowChangeCallback& callback)
{
    return PrivacyWindowManagerClient::GetInstance().UnregisterWindowManagerAgent(
        WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT, g_floatWindowCallback);
}

int32_t WindowManagerLoader::RegisterPipWindowListener(const WindowChangeCallback& callback)
{
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return 0;
    }
    if (g_pipWindowCallback == nullptr) {
        g_pipWindowCallback = new (std::nothrow) PrivacyWindowManagerAgent(callback);
        if (g_pipWindowCallback == nullptr) {
            return ERR_MALLOC_FAILED;
        }
    }
    return PrivacyWindowManagerClient::GetInstance().RegisterWindowManagerAgent(
        WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW, g_pipWindowCallback);
}

int32_t WindowManagerLoader::UnregisterPipWindowListener(const WindowChangeCallback& callback)
{
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return 0;
    }
    return PrivacyWindowManagerClient::GetInstance().UnregisterWindowManagerAgent(
        WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW, g_pipWindowCallback);
}

void WindowManagerLoader::AddDeathCallback(void (*callback)())
{
    PrivacyWindowManagerClient::GetInstance().AddDeathCallback(callback);
}

extern "C" {
void* Create()
{
    return reinterpret_cast<void*>(new (std::nothrow) WindowManagerLoader);
}

void Destroy(void* loaderPtr)
{
    WindowManagerLoaderInterface* loader = reinterpret_cast<WindowManagerLoaderInterface*>(loaderPtr);
    if (loader != nullptr) {
        delete loader;
    }
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
