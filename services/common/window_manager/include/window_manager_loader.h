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

#ifndef WINDOW_MANAGER_LOADER_H
#define WINDOW_MANAGER_LOADER_H
#include <string>
namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string WINDOW_MANAGER_PATH = "libaccesstoken_window_manager.z.so";

using WindowChangeCallback = void (*)(uint32_t, bool);
class WindowManagerLoaderInterface {
public:
    WindowManagerLoaderInterface() {}
    virtual ~WindowManagerLoaderInterface() {}
    virtual int32_t RegisterFloatWindowListener(const WindowChangeCallback& callback);
    virtual int32_t UnregisterFloatWindowListener(const WindowChangeCallback& callback);

    virtual int32_t RegisterPipWindowListener(const WindowChangeCallback& callback);
    virtual int32_t UnregisterPipWindowListener(const WindowChangeCallback& callback);

    virtual void AddDeathCallback(void (*callback)());
};

class WindowManagerLoader final: public WindowManagerLoaderInterface {
    int32_t RegisterFloatWindowListener(const WindowChangeCallback& callback);
    int32_t UnregisterFloatWindowListener(const WindowChangeCallback& callback);

    int32_t RegisterPipWindowListener(const WindowChangeCallback& callback);
    int32_t UnregisterPipWindowListener(const WindowChangeCallback& callback);

    void AddDeathCallback(void (*callback)());
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
#endif // WINDOW_MANAGER_LOADER_H