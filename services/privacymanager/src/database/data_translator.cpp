/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

void DataTranslator::GetDefaultTimeRange(int64_t& begin, int64_t& end)
{
    int64_t now = AccessToken::TimeUtil::GetCurrentTimestamp();
    int64_t beginTime = now - LATEST_RECORD_TIME;
    begin = (beginTime < 0) ? 0 : beginTime;
    end = now;
}

int32_t DataTranslator::TranslationIntoGenericValues(const PermissionUsedRequest& request,
    GenericValues& andGenericValues)
{
    // add tokenId to condition, tokenId may be 0, if 0 ignore it when compare with cache and create the sql
    andGenericValues.Put(PrivacyFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(request.tokenId));

    int64_t begin = request.beginTimeMillis;
    int64_t end = request.endTimeMillis;

    if ((begin < 0) || (end < 0) || (begin > end)) {
        return Constant::FAILURE;
    }

    if (begin == 0 && end == 0) {
        GetDefaultTimeRange(begin, end);
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
    } else if (flag == FLAG_PERMISSION_SECURITY_ACCESS_DETAIL) {
        // The NORMAL_TYPE value here serves no functional purpose; it is only used to add a key.
        andGenericValues.Put(PrivacyFiledConst::FIELD_USED_TYPE, static_cast<int32_t>(PermissionUsedType::NORMAL_TYPE));
    }

    return Constant::SUCCESS;
}

#ifdef REMOTE_PRIVACY_ENABLE
int32_t DataTranslator::TranslationRemoteRequestIntoGenericValues(const PermissionUsedRequest& request,
    GenericValues& andGenericValues)
{
    int64_t begin = request.beginTimeMillis;
    int64_t end = request.endTimeMillis;

    if ((begin < 0) || (end < 0) || (begin > end)) {
        return Constant::FAILURE;
    }

    if (begin == 0 && end == 0) {
        GetDefaultTimeRange(begin, end);
    }

    if (begin != 0) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN, begin);
    }
    if (end != 0) {
        andGenericValues.Put(PrivacyFiledConst::FIELD_TIMESTAMP_END, end);
    }

    return Constant::SUCCESS;
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
