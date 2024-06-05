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

#ifndef SCREENLOCK_MANAGER_ACCESS_LOADER_H
#define SCREENLOCK_MANAGER_ACCESS_LOADER_H

#include <string>
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
    const int32_t DEFAULT_VALUE = -1;
}
const static std::string SCREENLOCK_MANAGER_LIBPATH = "libaccesstoken_screenlock_manager.z.so";

class ScreenLockManagerAccessLoaderInterface {
public:
    ScreenLockManagerAccessLoaderInterface() {}
    virtual ~ScreenLockManagerAccessLoaderInterface() {}
    virtual bool IsScreenLocked();
};

class ScreenLockManagerAccessLoader final: public ScreenLockManagerAccessLoaderInterface {
    bool IsScreenLocked() override;
};

#ifdef __cplusplus
extern "C" {
#endif
    void* Create();
    void Destroy(void* loaderPtr);
#ifdef __cplusplus
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SCREENLOCK_MANAGER_ACCESS_LOADER_H