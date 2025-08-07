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
#include "ani_error.h"
#include "ani_request_base.h"
#include "ani_utils.h"
#ifdef EVENTHANDLER_ENABLE
#include "event_handler.h"
#include "event_queue.h"
#endif
#include "permission_grant_info.h"
#include "perm_state_change_callback_customize.h"
#include "token_callback_stub.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct RequestAsyncContext : public RequestAsyncContextBase {
    RequestAsyncContext(ani_vm* vm, ani_env* env);
    ~RequestAsyncContext() override;
    void StartExtensionAbility() override;
    bool IsDynamicRequest();
    void ProcessUIExtensionCallback(const OHOS::AAFwk::Want& result) override;
    void HandleResult() override;
    ani_object WrapResult() override;
    bool CheckDynamicRequest() override;
    void UpdateGrantPermissionResultOnly(std::vector<int32_t>& newGrantResults);

    bool needDynamicRequest = true;
    std::vector<std::string> permissionList;
    std::vector<int32_t> grantResults;
    std::vector<int32_t> permissionsState;
    std::vector<bool> dialogShownResults;
    std::vector<int32_t> permissionQueryResults;
    std::vector<int32_t> errorReasons;
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
