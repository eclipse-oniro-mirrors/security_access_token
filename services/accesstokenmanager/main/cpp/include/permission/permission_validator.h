/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_VALIDATOR_H
#define PERMISSION_VALIDATOR_H
#include "permission_def.h"
#include "permission_state_full.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionValidator final {
public:
    PermissionValidator() {}
    ~PermissionValidator() {}

    static bool IsPermissionNameValid(const std::string& permissionName);
    static bool IsPermissionFlagValid(int flag);
    static bool IsPermissionDefValid(const PermissionDef& permDef);
    static bool IsPermissionStateValid(const PermissionStateFull& permState);
    static void FilterInvalidPermissionDef(
        const std::vector<PermissionDef>& permList, std::vector<PermissionDef>& result);
    static void FilterInvalidPermissionState(
        const std::vector<PermissionStateFull>& permList, std::vector<PermissionStateFull>& result);
    static bool IsGrantModeValid(int grantMode);
    static bool IsGrantStatusValid(int grantStaus);
private:
    static void DeduplicateResDevID(const PermissionStateFull& permState, PermissionStateFull& result);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // PERMISSION_VALIDATOR_H

