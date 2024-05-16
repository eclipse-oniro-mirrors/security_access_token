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

#include "active_change_response_info.h"
#include "constant.h"
#include "data_validator.h"
#include "permission_used_type.h"
#include "privacy_field_const.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int64_t LATEST_RECORD_TIME = 7 * Constant::ONE_DAY_MILLISECONDS;
}
int32_t DataTranslator::TranslationIntoGenericValues(const PermissionUsedRequest& request,
    GenericValues& andGenericValues)
{
    int64_t begin = request.beginTimeMillis;
    int64_t end = request.endTimeMillis;

    if ((begin < 0) || (end < 0) || (begin > end)) {
        return Constant::FAILURE;
    }

    if (begin == 0 && end == 0) {
        int64_t beginTime = TimeUtil::GetCurrentTimestamp() - LATEST_RECORD_TIME;
        begin = (beginTime < 0) ? 0 : beginTime;
        end = TimeUtil::GetCurrentTimestamp();
    }

    if (begin != 0) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN, begin);
    }
    if (end != 0) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_END, end);
    }

    PermissionUsageFlagEnum flag = request.flag;

    if (!DataValidator::IsPermissionUsedFlagValid(flag)) {
        return Constant::FAILURE;
    }

    if (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, static_cast<int32_t>(PERM_ACTIVE_IN_LOCKED));
    } else if (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS, static_cast<int32_t>(PERM_ACTIVE_IN_UNLOCKED));
    } else if (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_BACKGROUND) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_STATUS, static_cast<int32_t>(PERM_ACTIVE_IN_BACKGROUND));
    } else if (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_STATUS, static_cast<int32_t>(PERM_ACTIVE_IN_FOREGROUND));
    }

    return Constant::SUCCESS;
}

int32_t DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord(const GenericValues& inGenericValues,
    PermissionUsedRecord& permissionRecord)
{
    int32_t accessCount = inGenericValues.GetInt(PrivacyFiledConst::FIELD_ACCESS_COUNT);
    int32_t rejectCount = inGenericValues.GetInt(PrivacyFiledConst::FIELD_REJECT_COUNT);
    std::string permission;
    int32_t opCode = inGenericValues.GetInt(PrivacyFiledConst::FIELD_OP_CODE);
    if (!Constant::TransferOpcodeToPermission(opCode, permission)) {
        return Constant::FAILURE;
    }

    int64_t timestamp = inGenericValues.GetInt64(PrivacyFiledConst::FIELD_TIMESTAMP);
    permissionRecord.permissionName = permission;

    if (accessCount != 0) {
        permissionRecord.accessCount = accessCount;
        permissionRecord.lastAccessTime = timestamp;
        permissionRecord.lastAccessDuration = inGenericValues.GetInt64(PrivacyFiledConst::FIELD_ACCESS_DURATION);
    }

    if (rejectCount != 0) {
        permissionRecord.rejectCount = rejectCount;
        permissionRecord.lastRejectTime = timestamp;
    }

    if (inGenericValues.GetInt(PrivacyFiledConst::FIELD_FLAG) == 0) {
        return Constant::SUCCESS;
    }

    UsedRecordDetail detail;
    detail.status = inGenericValues.GetInt(PrivacyFiledConst::FIELD_STATUS);
    int32_t lockScreenStatus = inGenericValues.GetInt(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS);
    detail.lockScreenStatus = lockScreenStatus == VariantValue::DEFAULT_VALUE ?
        LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED : lockScreenStatus;
    int32_t type = inGenericValues.GetInt(PrivacyFiledConst::FIELD_USED_TYPE);
    detail.type = static_cast<PermissionUsedType>(type);
    if (permissionRecord.lastAccessTime > 0) {
        detail.timestamp = permissionRecord.lastAccessTime;
        detail.accessDuration = inGenericValues.GetInt64(PrivacyFiledConst::FIELD_ACCESS_DURATION);
        detail.count = accessCount;
        permissionRecord.accessRecords.emplace_back(detail);
    }
    if (permissionRecord.lastRejectTime > 0) {
        detail.timestamp = permissionRecord.lastRejectTime;
        detail.count = rejectCount;
        permissionRecord.rejectRecords.emplace_back(detail);
    }
    return Constant::SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS