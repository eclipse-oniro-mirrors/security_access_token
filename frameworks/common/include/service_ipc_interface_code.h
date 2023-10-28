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

#ifndef SERVICE_IPC_INTERFACE_CODE_H
#define SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class AccessAppServiceInterfaceCode {
    TRANSACT_ON_FOREGROUND_APPLICATION_CHANGED = 0,
};

enum class AccessAbilityServiceInterfaceCode {
    START_ABILITY_ADD_CALLER = 1005,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SERVICE_IPC_INTERFACE_CODE_H
