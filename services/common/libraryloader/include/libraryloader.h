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

#ifndef ACCESS_TOKEN_LIBRARY_LOADER_H
#define ACCESS_TOKEN_LIBRARY_LOADER_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {

class LibraryLoader {
public:
    LibraryLoader(const std::string& path);
    ~LibraryLoader();
    template<typename T> T* GetObject()
    {
        return reinterpret_cast<T*>(instance_);
    };

private:
    void* handle_ = nullptr;
    void* instance_ = nullptr;
    void Create();
    void Destroy();
    bool PrintErrorLog(const std::string& targetName);
};
} // AccessToken
} // Security
} // OHOS
#endif // ACCESS_TOKEN_LIBRARY_LOADER_H