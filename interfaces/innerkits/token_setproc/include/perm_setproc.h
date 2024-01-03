/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PERM_SETPROC_H
#define PERM_SETPROC_H
#include <vector>
#include "setproc_common.h"
namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t AddPermissionToKernel(
    uint32_t tokenID, const std::vector<uint32_t>& opCodeList, const std::vector<bool>& statusList);
int32_t RemovePermissionFromKernel(uint32_t tokenID);
int32_t SetPermissionToKernel(uint32_t tokenID, int32_t opCode, bool status);
int32_t GetPermissionFromKernel(uint32_t tokenID, int32_t opCode, bool& isGranted);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
