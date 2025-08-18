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
#ifndef ANI_REQUEST_BASE_H
#define ANI_REQUEST_BASE_H

#include "ability_context.h"
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
enum AniRequestType {
    REQUEST_PERMISSIONS_FROM_USER,
    REQUEST_PERMISSION_ON_SETTING,
    REQUEST_GLOBAL_SWITCH_ON_SETTING
};

struct RequestAsyncContextBase {
    AccessTokenID tokenId = 0;
    std::string bundleName;
    PermissionGrantInfo info;
    int32_t instanceId = -1;
    std::shared_ptr<OHOS::AbilityRuntime::Context> stageContext_ = nullptr;
    bool uiExtensionFlag = false;
    bool releaseFlag = false;
    bool uiContentFlag = false;
    std::mutex lockReleaseFlag;

    // result after requesting
    AtmResult result_;
    std::atomic<bool> needDynamicRequest_ = true;

#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
#endif
    std::thread::id threadId_;
    ani_vm* vm_ = nullptr;
    ani_env* env_ = nullptr;
    ani_ref callbackRef_ = nullptr;
    AniRequestType contextType_;

    RequestAsyncContextBase(ani_vm* vm, ani_env* env, AniRequestType type);
    virtual ~RequestAsyncContextBase() = default;
    bool FillInfoFromContext(const ani_object& aniContext);
    void FinishCallback();
    void GetInstanceId();
    void Clear();
    AniRequestType GetType();

    virtual bool IsSameRequest(const std::shared_ptr<RequestAsyncContextBase> other);
    virtual void CopyResult(const std::shared_ptr<RequestAsyncContextBase> other);
    virtual void ProcessFailResult(int32_t code);

    virtual bool NoNeedUpdate() = 0;
    virtual int32_t ConvertErrorCode(int32_t code) = 0;
    virtual void ProcessUIExtensionCallback(const OHOS::AAFwk::Want& result) = 0;
    virtual ani_object WrapResult(ani_env* env) = 0;
    virtual void StartExtensionAbility(std::shared_ptr<RequestAsyncContextBase> asyncContext) = 0;
    virtual bool CheckDynamicRequest() = 0;
};

class RequestInstanceControl {
public:
    void AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContextBase> asyncContext);
    void ExecCallback(int32_t id);
    void UpdateQueueData(const std::shared_ptr<RequestAsyncContextBase> asyncContext);
private:
    std::map<int32_t, std::vector<std::shared_ptr<RequestAsyncContextBase>>> instanceIdMap_;
    std::mutex instanceIdMutex_;
};

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(const std::shared_ptr<RequestAsyncContextBase> reqContext);
    ~UIExtensionCallback();
    
    void SetSessionId(int32_t sessionId);
    void SetRequestInstanceControl(std::shared_ptr<RequestInstanceControl> controllerInstance);
    void ReleaseHandler(int32_t code);
    void OnRelease(int32_t releaseCode);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);

protected:
    std::shared_ptr<RequestInstanceControl> controllerInstance_ = nullptr;
    std::shared_ptr<RequestAsyncContextBase> reqContext_ = nullptr;

private:
    int32_t sessionId_ = 0;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* ANI_REQUEST_BASE_H */
