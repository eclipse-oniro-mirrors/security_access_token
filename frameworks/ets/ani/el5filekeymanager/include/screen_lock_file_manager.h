/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SCREEN_LOCK_FILE_MANAGER_H
#define SCREEN_LOCK_FILE_MANAGER_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum AccessStatus {
    ACCESS_DENIED = -1,
    ACCESS_GRANTED = 0
};

enum ReleaseStatus {
    RELEASE_DENIED = -1,
    RELEASE_GRANTED = 0
};

enum KeyStatus {
    KEY_NOT_EXIST = -2,
    KEY_RELEASED = -1,
    KEY_EXIST = 0
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif //SCREEN_LOCK_FILE_MANAGER_H
