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

#ifndef OHOS_ABILITY_ACCESS_REQUEST_PERMISSION_ON_SETTING_H
#define OHOS_ABILITY_ACCESS_REQUEST_PERMISSION_ON_SETTING_H

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "accesstoken_kit.h"
#include "cj_common_ffi.h"
#include "cj_lambda.h"
#include "permission_grant_info.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace CJSystemapi {

struct RequestPermOnSettingAsyncContext {
    OHOS::Security::AccessToken::AccessTokenID tokenId = 0;
    OHOS::Security::AccessToken::PermissionGrantInfo info;
    int32_t errorCode = -1;
    std::vector<std::string> permissionList;
    std::vector<int32_t> stateList;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<AbilityRuntime::UIExtensionContext> uiExtensionContext;
    bool uiAbilityFlag = false;
    bool releaseFlag = false;
    std::function<void(RetDataCArrI32)> callbackRef =  nullptr;
};

struct RequestOnSettingAsyncContextHandle {
    explicit RequestOnSettingAsyncContextHandle(std::shared_ptr<RequestPermOnSettingAsyncContext>& requestAsyncContext)
    {
        asyncContextPtr = requestAsyncContext;
    }

    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContextPtr;
};

class PermissonOnSettingUICallback {
public:
    explicit PermissonOnSettingUICallback(const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext);
    ~PermissonOnSettingUICallback();
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
    std::shared_ptr<RequestPermOnSettingAsyncContext> reqContext_ = nullptr;
};

class FfiRequestPermissionOnSetting {
public:
    static void RequestPermissionOnSetting(OHOS::AbilityRuntime::Context* context, CArrString cPermissionList,
        const std::function<void(RetDataCArrI32)>& callbackRef);
private:
    static bool ParseRequestPermissionOnSetting(OHOS::AbilityRuntime::Context* context, CArrString cPermissionList,
        const std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext);
};
}
}

#endif