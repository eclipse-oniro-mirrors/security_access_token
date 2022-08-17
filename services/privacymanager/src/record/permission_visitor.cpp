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

#include "permission_visitor.h"
#include "field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
void PermissionVisitor::TranslationIntoGenericValues(const PermissionVisitor& visitor, GenericValues& values)
{
    values.Put(FIELD_TOKEN_ID, (int32_t)visitor.tokenId);
    values.Put(FIELD_IS_REMOTE_DEVICE, visitor.isRemoteDevice ? 1 : 0);
    values.Put(FIELD_DEVICE_ID, visitor.deviceId);
    values.Put(FIELD_USER_ID, visitor.userId);
    values.Put(FIELD_BUNDLE_NAME, visitor.bundleName);
}

void PermissionVisitor::TranslationIntoPermissionVisitor(const GenericValues& values, PermissionVisitor& visitor)
{
    visitor.id = values.GetInt(FIELD_ID);
    visitor.tokenId = (AccessTokenID)values.GetInt(FIELD_TOKEN_ID);
    visitor.isRemoteDevice = values.GetInt(FIELD_IS_REMOTE_DEVICE);
    visitor.deviceId = values.GetString(FIELD_DEVICE_ID);
    visitor.userId = values.GetInt(FIELD_USER_ID);
    visitor.bundleName = values.GetString(FIELD_BUNDLE_NAME);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS