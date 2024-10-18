/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "perm_active_status_customized_cbk.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
PermActiveStatusCustomizedCbk::PermActiveStatusCustomizedCbk()
{}

PermActiveStatusCustomizedCbk::PermActiveStatusCustomizedCbk(
    const std::vector<std::string>& permList) : permList_(permList)
{}

PermActiveStatusCustomizedCbk::~PermActiveStatusCustomizedCbk()
{}

void PermActiveStatusCustomizedCbk::GetPermList(std::vector<std::string>& permList) const
{
    permList = permList_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
