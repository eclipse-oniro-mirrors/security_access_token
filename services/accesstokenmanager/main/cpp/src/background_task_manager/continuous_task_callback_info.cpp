/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "continuous_task_callback_info.h"
#include "accesstoken_log.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ContinuousTaskCallbackInfo"
};
} // namespace
bool ContinuousTaskCallbackInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(typeId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteUint32 failed.");
        return false;
    }

    if (!parcel.WriteInt32(creatorUid_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteInt32(creatorPid_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteBool(isFromWebview_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteBool failed.");
        return false;
    }

    std::u16string u16AbilityName = Str8ToStr16(abilityName_);
    if (!parcel.WriteString16(u16AbilityName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString16 failed.");
        return false;
    }

    if (!parcel.WriteBool(isBatchApi_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteBool failed.");
        return false;
    }

    if (!parcel.WriteUInt32Vector(typeIds_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteUInt32Vector failed.");
        return false;
    }

    if (!parcel.WriteInt32(abilityId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 failed.");
        return false;
    }

    if (!parcel.WriteUint64(tokenId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteUint64 failed.");
        return false;
    }
    return true;
}

ContinuousTaskCallbackInfo *ContinuousTaskCallbackInfo::Unmarshalling(Parcel &parcel)
{
    auto object = new (std::nothrow) ContinuousTaskCallbackInfo();
    if ((object != nullptr) && !object->ReadFromParcel(parcel)) {
        delete object;
        object = nullptr;
    }

    return object;
}

bool ContinuousTaskCallbackInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadUint32(typeId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadUint32 failed.");
        return false;
    }

    if (!parcel.ReadInt32(creatorUid_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }

    if (!parcel.ReadInt32(creatorUid_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }

    int32_t pid;
    if (!parcel.ReadInt32(pid)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }
    creatorPid_ = static_cast<pid_t>(pid);

    if (!parcel.ReadBool(isFromWebview_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadBool failed.");
        return false;
    }

    std::u16string u16AbilityName;
    if (!parcel.ReadString16(u16AbilityName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString16 failed.");
        return false;
    }
    abilityName_ = Str16ToStr8(u16AbilityName);

    if (!parcel.ReadBool(isBatchApi_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadBool failed.");
        return false;
    }

    if (!parcel.ReadUInt32Vector(&typeIds_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadUInt32Vector failed.");
        return false;
    }

    if (!parcel.ReadInt32(abilityId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 failed.");
        return false;
    }

    if (!parcel.ReadUint64(tokenId_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadUint64 failed.");
        return false;
    }
    return true;
}

uint64_t ContinuousTaskCallbackInfo::GetFullTokenId() const
{
    return tokenId_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
