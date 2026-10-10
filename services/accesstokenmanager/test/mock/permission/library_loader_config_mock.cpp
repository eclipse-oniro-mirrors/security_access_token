/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <new>
#include <string>

#include "json_parse_loader.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

LibraryLoader::LibraryLoader(const std::string& path, const std::string& createSymbol,
    const std::string& destroySymbol)
    : createSymbol_(createSymbol), destroySymbol_(destroySymbol)
{
    if (path == CONFIG_PARSE_LIBPATH) {
        instance_ = new (std::nothrow) ConfigPolicLoader();
    } else {
        instance_ = nullptr;
    }
    handle_ = nullptr;
}

LibraryLoader::~LibraryLoader() {}

void LibraryLoader::PrintErrorLog(const std::string& targetName) {}

void LibraryLoader::Create() {}

void LibraryLoader::Destroy() {}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
