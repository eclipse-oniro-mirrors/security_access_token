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

#ifndef PERMISSION_UESD_RECORD_NODE_H
#define PERMISSION_UESD_RECORD_NODE_H

#include <memory>
#include "permission_record.h"
#include "rwlock.h"
namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionUsedRecordNode {
    std::weak_ptr<PermissionUsedRecordNode> pre;
    std::shared_ptr<PermissionUsedRecordNode> next;
    PermissionRecord record;
    
    PermissionUsedRecordNode() = default;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_UESD_RECORD_NODE_H
