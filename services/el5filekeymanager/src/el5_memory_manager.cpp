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
#include "el5_memory_manager.h"

#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t MAX_RUNNING_NUM = 256;
std::recursive_mutex g_instanceMutex;
}

El5MemoryManager& El5MemoryManager::GetInstance()
{
    static El5MemoryManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            El5MemoryManager* tmp = new (std::nothrow) El5MemoryManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void El5MemoryManager::AddFunctionRuningNum()
{
    std::lock_guard<std::mutex> lock(callNumberMutex_);
    callFuncRunningNum_++;
    if (callFuncRunningNum_ > MAX_RUNNING_NUM) {
        LOG_WARN("The num of working function (%{public}d) over %{public}d.", callFuncRunningNum_, MAX_RUNNING_NUM);
    }
}

void El5MemoryManager::DecreaseFunctionRuningNum()
{
    std::lock_guard<std::mutex> lock(callNumberMutex_);
    callFuncRunningNum_--;
}

bool El5MemoryManager::IsFunctionFinished()
{
    std::lock_guard<std::mutex> lock(callNumberMutex_);
    if (callFuncRunningNum_ == 0) {
        return true;
    }
    LOG_WARN("Not allowed to unload service, callFuncRunningNum_ is %{public}d.", callFuncRunningNum_);
    return false;
}

bool El5MemoryManager::IsAllowUnloadService()
{
    std::lock_guard<std::mutex> lock(isAllowUnloadServiceMutex_);
    return isAllowUnloadService_;
}

void El5MemoryManager::SetIsAllowUnloadService(bool allow)
{
    LOG_INFO("The allow flag is (%{public}d).", allow);
    std::lock_guard<std::mutex> lock(isAllowUnloadServiceMutex_);
    isAllowUnloadService_ = allow;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
