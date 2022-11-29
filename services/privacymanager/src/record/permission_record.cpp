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

#include "permission_record.h"
#include "privacy_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
void PermissionRecord::TranslationIntoGenericValues(const PermissionRecord& record, GenericValues& values)
{
    values.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(record.tokenId));
    values.Put(PrivacyFiledConst::FIELD_OP_CODE, record.opCode);
    values.Put(PrivacyFiledConst::FIELD_STATUS, record.status);
    values.Put(PrivacyFiledConst::FIELD_TIMESTAMP, record.timestamp);
    values.Put(PrivacyFiledConst::FIELD_ACCESS_DURATION, record.accessDuration);
    values.Put(PrivacyFiledConst::FIELD_ACCESS_COUNT, record.accessCount);
    values.Put(PrivacyFiledConst::FIELD_REJECT_COUNT, record.rejectCount);
}

void PermissionRecord::TranslationIntoPermissionRecord(const GenericValues& values, PermissionRecord& record)
{
    record.tokenId = values.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID);
    record.opCode = values.GetInt(PrivacyFiledConst::FIELD_OP_CODE);
    record.status = values.GetInt(PrivacyFiledConst::FIELD_STATUS);
    record.timestamp = values.GetInt64(PrivacyFiledConst::FIELD_TIMESTAMP);
    record.accessDuration = values.GetInt64(PrivacyFiledConst::FIELD_ACCESS_DURATION);
    record.accessCount = values.GetInt(PrivacyFiledConst::FIELD_ACCESS_COUNT);
    record.rejectCount = values.GetInt(PrivacyFiledConst::FIELD_REJECT_COUNT);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS