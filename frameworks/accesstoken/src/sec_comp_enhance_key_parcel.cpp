/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "sec_comp_enhance_key_parcel.h"

#include "accesstoken_common_log.h"
#include "parcel_utils.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
SecCompEnhanceKeyParcel::~SecCompEnhanceKeyParcel()
{
    if (memset_s(enhanceKey.key.data, MAX_HMAC_SIZE, 0, MAX_HMAC_SIZE) != EOK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Clear enhance key failed.");
    }
    enhanceKey.key.size = 0;
    enhanceKey.epoch = 0;
}

bool SecCompEnhanceKeyParcel::Marshalling(Parcel& out) const
{
    if ((enhanceKey.key.size == 0) || (enhanceKey.key.size > MAX_HMAC_SIZE)) {
        return false;
    }
    RETURN_IF_FALSE(out.WriteUint64(enhanceKey.epoch));
    RETURN_IF_FALSE(out.WriteUint32(enhanceKey.key.size));
    RETURN_IF_FALSE(out.WriteBuffer(enhanceKey.key.data, enhanceKey.key.size));
    return true;
}

SecCompEnhanceKeyParcel* SecCompEnhanceKeyParcel::Unmarshalling(Parcel& in)
{
    auto* enhanceKeyParcel = new (std::nothrow) SecCompEnhanceKeyParcel();
    if (enhanceKeyParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadUint64(enhanceKeyParcel->enhanceKey.epoch), enhanceKeyParcel);
    RELEASE_IF_FALSE(in.ReadUint32(enhanceKeyParcel->enhanceKey.key.size), enhanceKeyParcel);
    if ((enhanceKeyParcel->enhanceKey.key.size == 0) ||
        (enhanceKeyParcel->enhanceKey.key.size > MAX_HMAC_SIZE)) {
        delete enhanceKeyParcel;
        return nullptr;
    }
    const uint8_t* ptr = in.ReadBuffer(enhanceKeyParcel->enhanceKey.key.size);
    if (ptr == nullptr) {
        delete enhanceKeyParcel;
        return nullptr;
    }
    if (memcpy_s(enhanceKeyParcel->enhanceKey.key.data, MAX_HMAC_SIZE, ptr,
        enhanceKeyParcel->enhanceKey.key.size) != EOK) {
        delete enhanceKeyParcel;
        return nullptr;
    }
    return enhanceKeyParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
