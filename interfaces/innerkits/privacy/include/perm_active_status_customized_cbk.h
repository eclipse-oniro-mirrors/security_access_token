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

#ifndef PERM_ACTIVE_STATUS_CUSTOMIZED_CBK_H
#define PERM_ACTIVE_STATUS_CUSTOMIZED_CBK_H

#include <string>
#include <vector>

#include "access_token.h"
#include "active_change_response_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermActiveStatusCustomizedCbk {
public:
    PermActiveStatusCustomizedCbk();
    explicit PermActiveStatusCustomizedCbk(const std::vector<std::string>& permList);
    virtual ~PermActiveStatusCustomizedCbk();

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result) = 0;

    void GetPermList(std::vector<std::string>& permList) const;

private:
    std::vector<std::string> permList_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // PERM_ACTIVE_STATUS_CUSTOMIZED_CBK_H