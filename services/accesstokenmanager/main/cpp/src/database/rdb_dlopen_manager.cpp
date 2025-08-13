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

#include "rdb_dlopen_manager.h"

#include <cerrno>
#include <dlfcn.h>

#include "access_token_error.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* RDB_SYMBOL_CREATE = "Create";
constexpr const char* RDB_SYMBOL_DESTROY = "Destroy";
constexpr const char* DELAY_DLCLOSE_TASK_NAME = "DelayDlclose";
constexpr int64_t DELAY_DLCLOSE_TIME_MILLISECONDS = 180 * 1000;

using CreateFunc = void* (*)(void);
using DestroyFunc = void (*)(void*);
}

RdbDlopenManager::RdbDlopenManager()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RdbDlopenManager");
}

#ifdef EVENTHANDLER_ENABLE
void RdbDlopenManager::InitEventHandler()
{
    eventRunner_ = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (eventRunner_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create a eventRunner.");
        return;
    }
    eventHandler_ = std::make_shared<AccessEventHandler>(eventRunner_);
}

std::shared_ptr<AccessEventHandler> RdbDlopenManager::GetEventHandler()
{
    std::lock_guard<std::mutex> lock(eventHandlerLock_);
    if (eventHandler_ == nullptr) {
        InitEventHandler();
    }
    return eventHandler_;
}
#endif

void RdbDlopenManager::Init()
{
    if (instance_ == nullptr) {
        return;
    }

    instance_->InitRdbHelper();
}

void RdbDlopenManager::Create(void* handle)
{
    if (handle == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dynamic open handle is nullptr.");
        return;
    }

    CreateFunc create = reinterpret_cast<CreateFunc>(dlsym(handle, RDB_SYMBOL_CREATE));
    if (create == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Find symbol %{public}s from %{public}s failed, errno is %{public}d, errMsg is %{public}s.",
            RDB_SYMBOL_CREATE, RDB_ADAPTER_LIBPATH, errno, dlerror());
        return;
    }
    instance_ = reinterpret_cast<AccessTokenDbLoaderInterface*>(create());

    Init();
}

void RdbDlopenManager::Destroy(void* handle)
{
    if (handle == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dynamic open handle is nullptr.");
        return;
    }

    DestroyFunc destroy = reinterpret_cast<DestroyFunc>(dlsym(handle, RDB_SYMBOL_DESTROY));
    if (destroy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Find symbol %{public}s from %{public}s failed, errno is %{public}d, errMsg is %{public}s.",
            RDB_SYMBOL_DESTROY, RDB_ADAPTER_LIBPATH, errno, dlerror());
        return;
    }

    if (instance_ == nullptr) {
        return;
    }

    destroy(instance_);
    instance_ = nullptr;
}

bool RdbDlopenManager::CleanUp()
{
    // if DestroyRdbHelper return false after 10 attempts, don't dlclose otherwise this may cause cppcrash
    return (instance_ != nullptr) ? instance_->DestroyRdbHelper() : true;
}

void RdbDlopenManager::DelayDlcloseHandle(int64_t delayTime)
{
#ifdef EVENTHANDLER_ENABLE
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler.");
        return;
    }

    eventHandler->ProxyRemoveTask(std::string(DELAY_DLCLOSE_TASK_NAME));

    std::function<void()> delayed = ([delayTime, this]() {
        LOGI(ATM_DOMAIN, ATM_TAG, "Delay dlclose rdb handle.");
        std::lock_guard<std::mutex> lock(handleMutex_);
        if (handle_ == nullptr) {
            return;
        }

        if (taskNum_ > 0) {
            LOGI(ATM_DOMAIN, ATM_TAG, "There is still %{public}d database call remain, wait for next task.",
                taskNum_.load());
            return;
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "There is no database call remain, clean up resource.");

        if (!CleanUp()) {
            return;
        }

        Destroy(handle_);
        dlclose(handle_);
        handle_ = nullptr;
    });
    eventHandler->ProxyPostTask(delayed, std::string(DELAY_DLCLOSE_TASK_NAME), delayTime);
#else
    LOGW(ATM_DOMAIN, ATM_TAG, "Eventhandler is not support!");
#endif
}

AccessTokenDbLoaderInterface* RdbDlopenManager::GetDbInstance()
{
    {
        std::lock_guard<std::mutex> lock(handleMutex_);
        if (handle_ == nullptr) {
            handle_ = dlopen(RDB_ADAPTER_LIBPATH, RTLD_LAZY);
            if (handle_ == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen %{public}s failed, errno is %{public}d, errMsg is %{public}s.",
                    RDB_ADAPTER_LIBPATH, errno, dlerror());
                return nullptr;
            }
        }

        if (instance_ == nullptr) {
            Create(handle_);
        }
    }

    DelayDlcloseHandle(DELAY_DLCLOSE_TIME_MILLISECONDS);
    return instance_;
}

int32_t RdbDlopenManager::Modify(const AtmDataType type, const GenericValues& modifyValue,
    const GenericValues& conditionValue)
{
    auto instance = GetDbInstance();
    if (instance == nullptr) {
        return AccessTokenError::ERR_LOAD_SO_FAILED;
    }

    ++taskNum_;
    int32_t res = instance->Modify(type, modifyValue, conditionValue);
    --taskNum_;
    return res;
}

int32_t RdbDlopenManager::Find(AtmDataType type, const GenericValues& conditionValue,
    std::vector<GenericValues>& results)
{
    auto instance = GetDbInstance();
    if (instance == nullptr) {
        return AccessTokenError::ERR_LOAD_SO_FAILED;
    }

    ++taskNum_;
    int32_t res = instance->Find(type, conditionValue, results);
    --taskNum_;
    return res;
}

int32_t RdbDlopenManager::DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
    auto instance = GetDbInstance();
    if (instance == nullptr) {
        return AccessTokenError::ERR_LOAD_SO_FAILED;
    }

    ++taskNum_;
    int32_t res = instance->DeleteAndInsertValues(delInfoVec, addInfoVec);
    --taskNum_;
    return res;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
