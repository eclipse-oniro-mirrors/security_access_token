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


#ifndef  ABILITY_ACCESS_CTRL_H
#define  ABILITY_ACCESS_CTRL_H

#include <atomic>
#include <map>
#include <mutex>

#include "ability.h"
#include "ability_manager_client.h"
#include "access_token.h"
#include "ani.h"
#include "permission_grant_info.h"
#include "token_callback_stub.h"
#include "ui_content.h"
#include "ui_extension_context.h"

std::mutex g_lockCache;

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef unsigned int AccessTokenID;
static std::atomic<int32_t> g_cnt = 0;
constexpr uint32_t REPORT_CNT = 10;
constexpr uint32_t VERIFY_TOKENID_INCONSISTENCY = 0;
const int32_t PARAM_DEFAULT_VALUE = -1;

static const char *PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";

struct AtManagerAsyncContext {
    AccessTokenID tokenId = 0;
    std::string permissionName;
    union {
        uint32_t flag = 0;
        uint32_t status;
    };
    int32_t result = RET_FAILED;
    int32_t errorCode = 0;
};

class AniContextCommon {
public:
    static constexpr int32_t MAX_PARAMS_ONE = 1;
    static constexpr int32_t MAX_PARAMS_TWO = 2;
    static constexpr int32_t MAX_PARAMS_THREE = 3;
    static constexpr int32_t MAX_PARAMS_FOUR = 4;
    static constexpr int32_t MAX_LENGTH = 256;
    static constexpr int32_t MAX_WAIT_TIME = 1000;
    static constexpr int32_t VALUE_MAX_LEN = 32;
};

struct PermissionParamCache {
    long long sysCommitIdCache = PARAM_DEFAULT_VALUE;
    int32_t commitIdCache = PARAM_DEFAULT_VALUE;
    int32_t handle = PARAM_DEFAULT_VALUE;
    std::string sysParamCache;
};

struct PermissionStatusCache {
    int32_t status;
    std::string paramValue;
};

static PermissionParamCache g_paramCache;
std::map<std::string, PermissionStatusCache> g_cache;

struct RequestAsyncContext {
    AccessTokenID tokenId = 0;
    std::string bundleName;
    bool needDynamicRequest = true;
    int32_t result = RET_SUCCESS;
    int32_t instanceId = -1;
    std::vector<std::string> permissionList;
    std::vector<int32_t> permissionsState;
    ani_object requestResult = nullptr;
    std::vector<bool> dialogShownResults;
    std::vector<int32_t> permissionQueryResults;
    Security::AccessToken::PermissionGrantInfo info;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<AbilityRuntime::UIExtensionContext> uiExtensionContext;
    bool uiAbilityFlag = false;
    bool uiExtensionFlag = false;
    bool uiContentFlag = false;
    bool releaseFlag = false;
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
#endif
};

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(const std::shared_ptr<RequestAsyncContext> &reqContext);
    ~UIExtensionCallback();
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result);
    void OnReceive(const OHOS::AAFwk::WantParams &request);
    void OnError(int32_t code, const std::string &name, const std::string &message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy);
    void OnDestroy();
    void ReleaseHandler(int32_t code);

private:
    int32_t sessionId_ = 0;
    std::shared_ptr<RequestAsyncContext> reqContext_ = nullptr;
};

class AuthorizationResult : public Security::AccessToken::TokenCallbackStub {
public:
    AuthorizationResult(std::shared_ptr<RequestAsyncContext> &data) : data_(data) {}
    virtual ~AuthorizationResult() override = default;

    virtual void GrantResultsCallback(
        const std::vector<std::string> &permissionList, const std::vector<int> &grantResults) override;
    virtual void WindowShownCallback() override;

private:
    std::shared_ptr<RequestAsyncContext> data_ = nullptr;
};

class RequestAsyncInstanceControl {
public:
    static void AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContext> &asyncContext);
    static void ExecCallback(int32_t id);
    static void CheckDynamicRequest(std::shared_ptr<RequestAsyncContext> &asyncContext, bool &isDynamic);

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

std::map<int32_t, std::vector<std::shared_ptr<RequestAsyncContext>>>
    RequestAsyncInstanceControl::instanceIdMap_;
std::mutex RequestAsyncInstanceControl::instanceIdMutex_;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // ABILITY_ACCESS_CTRL_H