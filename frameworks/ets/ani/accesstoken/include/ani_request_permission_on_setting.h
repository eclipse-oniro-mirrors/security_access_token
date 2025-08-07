/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef ANI_REQUEST_PERMISSION_ON_SETTING_H
#define ANI_REQUEST_PERMISSION_ON_SETTING_H

#include "access_token.h"
#include "ani.h"
#include "ani_error.h"
#include "ani_utils.h"
#ifdef EVENTHANDLER_ENABLE
#include "event_handler.h"
#include "event_queue.h"
#endif
#include "permission_grant_info.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct RequestPermOnSettingAsyncContext {
    virtual ~RequestPermOnSettingAsyncContext();
    AccessTokenID tokenId = 0;
    AtmResult result;
    PermissionGrantInfo info;

    int32_t instanceId = -1;
    bool isDynamic = true;
    std::vector<std::string> permissionList;
    ani_object requestResult = nullptr;
    std::vector<int32_t> stateList;

    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext = nullptr;
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> uiExtensionContext = nullptr;
    bool uiAbilityFlag = false;
    bool releaseFlag = false;
    std::mutex lockReleaseFlag;

#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventHandler> handler_ =
        std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    std::thread::id threadId;
    ani_vm* vm = nullptr;
    ani_env* env = nullptr;
    ani_object callback = nullptr;
    ani_ref callbackRef = nullptr;
};

class RequestOnSettingAsyncInstanceControl {
    public:
        static void AddCallbackByInstanceId(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext);
        static void ExecCallback(int32_t id);
        static void CheckDynamicRequest(
            std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext, bool& isDynamic);
        static void UpdateQueueData(const std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext);
    private:
        static std::map<int32_t, std::vector<std::shared_ptr<RequestPermOnSettingAsyncContext>>> instanceIdMap_;
        static std::mutex instanceIdMutex_;
};

class PermissonOnSettingUICallback {
public:
    explicit PermissonOnSettingUICallback(const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext);
    ~PermissonOnSettingUICallback();
    void SetSessionId(int32_t sessionId);
    void ReleaseHandler(int32_t code);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();

private:
    std::shared_ptr<RequestPermOnSettingAsyncContext> reqContext_ = nullptr;
    int32_t sessionId_ = 0;
};

void RequestPermissionOnSettingExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_array_ref permissionList, ani_object callback);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* ANI_REQUEST_PERMISSION_ON_SETTING_H */
