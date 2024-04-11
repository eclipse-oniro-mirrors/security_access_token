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

#include "libraryloader.h"

#include <dlfcn.h>
#include <string>

#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenLibLoader"};
typedef void* (*FUNC_CREATE) (void);
typedef void (*FUNC_DESTROY) (void*);
}

LibraryLoader::LibraryLoader(const std::string& path)
{
    handle_ = dlopen(path.c_str(), RTLD_LAZY);
    if (handle_ == nullptr) {
        PrintErrorLog(path);
        return;
    }
    Create();
}

LibraryLoader::~LibraryLoader()
{
    if (instance_ != nullptr) {
        Destroy();
    }
#ifndef FUZZ_ENABLE
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
#endif // FUZZ_ENABLE
}

bool LibraryLoader::PrintErrorLog(const std::string& targetName)
{
    char* error;
    if ((error = dlerror()) != nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get %{public}s failed, errMsg=%{public}s.",
            targetName.c_str(), error);
        return false;
    }
    return true;
}

void LibraryLoader::Create()
{
    void* (*create)(void) = reinterpret_cast<FUNC_CREATE>(dlsym(handle_, "Create"));
    if (!PrintErrorLog("Create")) {
        return;
    }
    instance_ = create();
}

void LibraryLoader::Destroy()
{
    void (*destroy)(void*) = reinterpret_cast<FUNC_DESTROY>(dlsym(handle_, "Destroy"));
    if (!PrintErrorLog("Destroy")) {
        return;
    }
    destroy(instance_);
    instance_ = nullptr;
}
} // AccessToken
} // Security
} // OHOS