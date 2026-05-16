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

#ifndef USER_POLICY_TYPES_H
#define USER_POLICY_TYPES_H

#include <set>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct UserPolicyChange {
    uint32_t permCode;
    bool isPersist = false;
    std::set<int32_t> changedUserList;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // USER_POLICY_TYPES_H
