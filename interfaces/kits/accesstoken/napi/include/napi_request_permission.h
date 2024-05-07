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
#ifndef INTERFACES_ACCESSTOKEN_KITS_NAPI_REQUEST_PERMISSION_H
#define INTERFACES_ACCESSTOKEN_KITS_NAPI_REQUEST_PERMISSION_H

#include "napi_context_common.h"
#include "permission_grant_info.h"
#include "token_callback_stub.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static int32_t curRequestCode_ = 0;
const std::string REQUEST_PERMISSION_CLASS_NAME = "requestPermission";
struct RequestAsyncContext : public AtManagerAsyncWorkData {
    explicit RequestAsyncContext(napi_env env) : AtManagerAsyncWorkData(env)
    {
        this->env = env;
    }

    AccessTokenID tokenId = 0;
    bool needDynamicRequest = true;
    int32_t result = RET_SUCCESS;
    std::vector<std::string> permissionList;
    std::vector<int32_t> permissionsState;
    napi_value requestResult = nullptr;
    std::vector<bool> dialogShownResults;
    std::vector<int32_t> permissionQueryResults;
    PermissionGrantInfo info;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<AbilityRuntime::UIExtensionContext> uiExtensionContext;
    bool uiAbilityFlag = false;
    bool uiExtensionFlag = false;
    bool uiContentFlag = false;
    bool releaseFlag = false;
};

struct RequestAsyncContextHandle {
    explicit RequestAsyncContextHandle(std::shared_ptr<RequestAsyncContext>& requestAsyncContext)
    {
        asyncContextPtr = requestAsyncContext;
    }

    std::shared_ptr<RequestAsyncContext> asyncContextPtr;
};

class RequestAsyncInstanceControl {
    public:
        static void AddCallbackByInstanceId(int32_t id, std::shared_ptr<RequestAsyncContext>& asyncContext);
        static void ExecCallback(int32_t id);
        static void CheckDynamicRequest(std::shared_ptr<RequestAsyncContext>& asyncContext, bool& isDynamic);
    private:
        static std::map<int32_t, std::vector<std::shared_ptr<RequestAsyncContext>>> instanceIdMap_;
        static std::mutex instanceIdMutex_;
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
    void ReleaseOrErrorHandle(int32_t code);

private:
    int32_t sessionId_ = 0;
    std::shared_ptr<RequestAsyncContext> reqContext_ = nullptr;
};

struct ResultCallback {
    std::vector<std::string> permissions;
    std::vector<int32_t> grantResults;
    std::vector<bool> dialogShownResults;
    int32_t requestCode;
    std::shared_ptr<RequestAsyncContext> data = nullptr;
};

class AuthorizationResult : public Security::AccessToken::TokenCallbackStub {
public:
    AuthorizationResult(int32_t requestCode, std::shared_ptr<RequestAsyncContext>& data)
        : requestCode_(requestCode), data_(data)
    {}
    virtual ~AuthorizationResult() override = default;

    virtual void GrantResultsCallback(const std::vector<std::string>& permissions,
        const std::vector<int>& grantResults) override;
    virtual void WindowShownCallback() override;

private:
    int32_t requestCode_ = 0;
    std::shared_ptr<RequestAsyncContext> data_ = nullptr;
};

class NapiRequestPermission {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static bool IsDynamicRequest(std::shared_ptr<RequestAsyncContext>& asyncContext);
    static napi_value RequestPermissionsFromUser(napi_env env, napi_callback_info info);
    static napi_value GetPermissionsStatus(napi_env env, napi_callback_info info);

private:
    static bool ParseRequestPermissionFromUser(const napi_env& env, const napi_callback_info& cbInfo,
        std::shared_ptr<RequestAsyncContext>& asyncContext);
    static void RequestPermissionsFromUserExecute(napi_env env, void* data);
    static void RequestPermissionsFromUserComplete(napi_env env, napi_status status, void* data);
    static bool ParseInputToGetQueryResult(const napi_env& env, const napi_callback_info& info,
        RequestAsyncContext& asyncContext);
    static void GetPermissionsStatusExecute(napi_env env, void *data);
    static void GetPermissionsStatusComplete(napi_env env, napi_status status, void *data);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* INTERFACES_ACCESSTOKEN_KITS_NAPI_REQUEST_PERMISSION_H */
