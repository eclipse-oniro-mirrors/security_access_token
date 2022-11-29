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

#include "data_translator.h"

#include "constant.h"
#include "privacy_field_const.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t DataTranslator::TranslationIntoGenericValues(const PermissionUsedRequest& request,
    GenericValues& andGenericValues, GenericValues& orGenericValues)
{
    int64_t begin = request.beginTimeMillis;
    int64_t end = request.endTimeMillis;
    if ((begin < 0) || (end < 0) || (begin > end)) {
        return Constant::FAILURE;
    }

    if (request.flag != FLAG_PERMISSION_USAGE_SUMMARY && request.flag != FLAG_PERMISSION_USAGE_DETAIL) {
        return Constant::FAILURE;
    }

    if (begin == 0 && end == 0) {
        int64_t beginTime = TimeUtil::GetCurrentTimestamp() - Constant::LATEST_RECORD_TIME;
        begin = (beginTime < 0) ? 0 : beginTime;
        end = TimeUtil::GetCurrentTimestamp();
    }

    if (begin != 0) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN, begin);
    }
    if (end != 0) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_END, end);
    }

    for (const auto& perm : request.permissionList) {
        int32_t opCode;
        if (Constant::TransferPermissionToOpcode(perm, opCode)) {
            orGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, opCode);
        } else {
            orGenericValues.Put(PrivacyFiledConst::FIELD_OP_CODE, Constant::OP_INVALID);
        }
    }
    return Constant::SUCCESS;
}

int32_t DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(const GenericValues& inGenericValues,
    PermissionUsedRecord& permissionRecord)
{
    std::string permission;
    int32_t opCode = inGenericValues.GetInt(PrivacyFiledConst::FIELD_OP_CODE);
    if (!Constant::TransferOpcodeToPermission(opCode, permission)) {
        return Constant::FAILURE;
    }

    int64_t timestamp = inGenericValues.GetInt64(PrivacyFiledConst::FIELD_TIMESTAMP);
    permissionRecord.permissionName = permission;

    if (inGenericValues.GetInt(PrivacyFiledConst::FIELD_ACCESS_COUNT) != 0) {
        permissionRecord.accessCount = inGenericValues.GetInt(PrivacyFiledConst::FIELD_ACCESS_COUNT);
        permissionRecord.lastAccessTime = timestamp;
        permissionRecord.lastAccessDuration = inGenericValues.GetInt64(PrivacyFiledConst::FIELD_ACCESS_DURATION);
    }

    if (inGenericValues.GetInt(PrivacyFiledConst::FIELD_REJECT_COUNT) != 0) {
        permissionRecord.rejectCount = inGenericValues.GetInt(PrivacyFiledConst::FIELD_REJECT_COUNT);
        permissionRecord.lastRejectTime = timestamp;
    }

    if (inGenericValues.GetInt(PrivacyFiledConst::FIELD_FLAG) == 0) {
        return Constant::SUCCESS;
    }

    UsedRecordDetail detail;
    detail.status = inGenericValues.GetInt(PrivacyFiledConst::FIELD_STATUS);
    if (permissionRecord.lastAccessTime > 0) {
        detail.timestamp = permissionRecord.lastAccessTime;
        detail.accessDuration = inGenericValues.GetInt64(PrivacyFiledConst::FIELD_ACCESS_DURATION);
        permissionRecord.accessRecords.emplace_back(detail);
    }
    if (permissionRecord.lastRejectTime > 0) {
        detail.timestamp = permissionRecord.lastRejectTime;
        permissionRecord.rejectRecords.emplace_back(detail);
    }
    return Constant::SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS