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
#ifndef ANI_REQUEST_PERMISSION_H
#define ANI_REQUEST_PERMISSION_H

#include <mutex>
#include <thread>
#include "access_token.h"
#include "ani.h"
#include "ani_common.h"
#include "ani_error.h"
#include "ani_utils.h"
#ifdef EVENTHANDLER_ENABLE
#include "event_handler.h"
#include "event_queue.h"
#endif
#include "permission_grant_info.h"
#include "perm_state_change_callback_customize.h"
#include "token_callback_stub.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct RequestAsyncContext {
    virtual ~RequestAsyncContext();
    AccessTokenID tokenId = 0;
    std::string bundleName;
    bool needDynamicRequest = true;
    AtmResult result;
    int32_t instanceId = -1;
    std::vector<std::string> permissionList;
    std::vector<int32_t> grantResults;
    std::vector<int32_t> permissionsState;
    std::vector<bool> dialogShownResults;
    std::vector<int32_t> permissionQueryResults;
    std::vector<int32_t> errorReasons;
    Security::AccessToken::PermissionGrantInfo info;
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext = nullptr;
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> uiExtensionContext = nullptr;
    bool uiAbilityFlag = false;
    bool uiExtensionFlag = false;
    bool uiContentFlag = false;
    bool releaseFlag = false;
    std::mutex loadlock;
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
#endif
    std::thread::id threadId;
    ani_vm* vm = nullptr;
    ani_env* env = nullptr;
    ani_object callback = nullptr;
    ani_ref callbackRef = nullptr;
};

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(const std::shared_ptr<RequestAsyncContext>& reqContext);
    ~UIExtensionCallback();
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void ReleaseHandler(int32_t code);

private:
    int32_t sessionId_ = 0;
    std::shared_ptr<RequestAsyncContext> reqContext_ = nullptr;
    std::atomic<bool> isOnResult_;
};

class AuthorizationResult : public Security::AccessToken::TokenCallbackStub {
public:
    AuthorizationResult(std::shared_ptr<RequestAsyncContext>& data) : data_(data) {}
    virtual ~AuthorizationResult() override = default;

    virtual void GrantResultsCallback(
        const std::vector<std::string>& permissionList, const std::vector<int32_t>& grantResults) override;
    virtual void WindowShownCallback() override;

private:
    std::shared_ptr<RequestAsyncContext> data_ = nullptr;
};

class RequestAsyncInstanceControl {
public:
    static void AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContext>& asyncContext);
    static void ExecCallback(int32_t id);
    static void CheckDynamicRequest(std::shared_ptr<RequestAsyncContext>& asyncContext, bool& isDynamic);

private:
    static std::map<int32_t, std::vector<std::shared_ptr<RequestAsyncContext>>> instanceIdMap_;
    static std::mutex instanceIdMutex_;
};

struct ResultCallback {
    std::vector<std::string> permissions;
    std::vector<int32_t> grantResults;
    std::vector<bool> dialogShownResults;
    std::shared_ptr<RequestAsyncContext> data = nullptr;
};

void RequestPermissionsFromUserExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_object aniContext, ani_array_ref permissionList, ani_object callback);

class RegisterPermStateChangeScopePtr : public std::enable_shared_from_this<RegisterPermStateChangeScopePtr>,
    public PermStateChangeCallbackCustomize {
public:
    explicit RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo);
    ~RegisterPermStateChangeScopePtr() override;
    void PermStateChangeCallback(PermStateChangeInfo& result) override;
    void SetCallbackRef(const ani_ref& ref);
    void SetValid(bool valid);
    void SetEnv(ani_env* env);

    void SetVm(ani_vm* vm);
    void SetThreadId(const std::thread::id threadId);
private:
    bool valid_ = true;
    std::mutex validMutex_;
    ani_env* env_ = nullptr;

    ani_vm* vm_ = nullptr;
    std::thread::id threadId_;
    ani_ref ref_ = nullptr;
};

struct RegisterPermStateChangeInf {
    ani_env* env = nullptr;
    ani_ref callbackRef = nullptr;
    int32_t errCode = RET_SUCCESS;
    std::string permStateChangeType;
    std::thread::id threadId;
    std::shared_ptr<RegisterPermStateChangeScopePtr> subscriber = nullptr;
    PermStateChangeScope scopeInfo;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* ANI_REQUEST_PERMISSION_H */
