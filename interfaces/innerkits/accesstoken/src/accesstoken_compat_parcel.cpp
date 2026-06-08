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

#include "accesstoken_compat_parcel.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t HapTokenInfoCompatUnmarshalling(OHOS::MessageParcel& data, HapTokenInfoCompatParcel& dataBlock)
{
    std::u16string bundleNameU16;
    if (!data.ReadString16(bundleNameU16)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read bundleName failed!");
        return ERR_READ_PARCEL_FAILED;
    }
    dataBlock.bundleName = Str16ToStr8(bundleNameU16);

    if (!data.ReadInt32(dataBlock.userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read userID failed!");
        return ERR_READ_PARCEL_FAILED;
    }

    if (!data.ReadInt32(dataBlock.instIndex)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read instIndex failed!");
        return ERR_READ_PARCEL_FAILED;
    }

    if (!data.ReadInt32(dataBlock.apiVersion)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read apiVersion failed!");
        return ERR_READ_PARCEL_FAILED;
    }

    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
