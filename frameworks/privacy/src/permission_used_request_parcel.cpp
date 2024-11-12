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

#include "permission_used_request_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionUsedRequestParcel::Marshalling(Parcel& out) const
{
    RETURN_IF_FALSE(out.WriteUint32(this->request.tokenId));
    RETURN_IF_FALSE(out.WriteBool(this->request.isRemote));
    RETURN_IF_FALSE(out.WriteString(this->request.deviceId));
    RETURN_IF_FALSE(out.WriteString(this->request.bundleName));

    RETURN_IF_FALSE(out.WriteUint32(this->request.permissionList.size()));
    for (const auto& perm : this->request.permissionList) {
        RETURN_IF_FALSE(out.WriteString(perm));
    }
    RETURN_IF_FALSE(out.WriteInt64(this->request.beginTimeMillis));
    RETURN_IF_FALSE(out.WriteInt64(this->request.endTimeMillis));
    RETURN_IF_FALSE(out.WriteInt32(this->request.flag));
    return true;
}

PermissionUsedRequestParcel* PermissionUsedRequestParcel::Unmarshalling(Parcel& in)
{
    auto* requestParcel = new (std::nothrow) PermissionUsedRequestParcel();
    if (requestParcel == nullptr) {
        return nullptr;
    }

    RELEASE_IF_FALSE(in.ReadUint32(requestParcel->request.tokenId), requestParcel);
    RELEASE_IF_FALSE(in.ReadBool (requestParcel->request.isRemote), requestParcel);
    RELEASE_IF_FALSE(in.ReadString(requestParcel->request.deviceId), requestParcel);
    RELEASE_IF_FALSE(in.ReadString(requestParcel->request.bundleName), requestParcel);

    uint32_t permSize = 0;
    RELEASE_IF_FALSE(in.ReadUint32(permSize), requestParcel);
    RELEASE_IF_FALSE(permSize <= MAX_PERMLIST_SIZE, requestParcel);
    for (uint32_t i = 0; i < permSize; i++) {
        std::string perm;
        RELEASE_IF_FALSE(in.ReadString(perm), requestParcel);
        requestParcel->request.permissionList.emplace_back(perm);
    }
    RELEASE_IF_FALSE(in.ReadInt64(requestParcel->request.beginTimeMillis), requestParcel);
    RELEASE_IF_FALSE(in.ReadInt64(requestParcel->request.endTimeMillis), requestParcel);
    int32_t flag;
    RELEASE_IF_FALSE(in.ReadInt32(flag), requestParcel);
    requestParcel->request.flag = static_cast<PermissionUsageFlagEnum>(flag);
    return requestParcel;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
