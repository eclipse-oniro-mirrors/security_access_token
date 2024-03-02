/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "process_data.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool ProcessData::Marshalling(Parcel &parcel) const
{
    return (parcel.WriteString(bundleName) && parcel.WriteInt32(pid) && parcel.WriteInt32(uid) &&
        parcel.WriteInt32(static_cast<int32_t>(state)) && parcel.WriteBool(isContinuousTask) &&
        parcel.WriteBool(isKeepAlive) && parcel.WriteBool(isFocused) && parcel.WriteInt32(requestProcCode) &&
        parcel.WriteInt32(processChangeReason) && parcel.WriteString(processName) &&
        parcel.WriteInt32(static_cast<int32_t>(processType)) && parcel.WriteInt32(extensionType) &&
        parcel.WriteInt32(renderUid) && parcel.WriteUint32(accessTokenId)) &&
        parcel.WriteBool(isTestMode);
}

bool ProcessData::ReadFromParcel(Parcel &parcel)
{
    bundleName = parcel.ReadString();
    pid = parcel.ReadInt32();
    uid = parcel.ReadInt32();
    state = static_cast<AppProcessState>(parcel.ReadInt32());
    isContinuousTask = parcel.ReadBool();
    isKeepAlive = parcel.ReadBool();
    isFocused = parcel.ReadBool();
    requestProcCode = parcel.ReadInt32();
    processChangeReason = parcel.ReadInt32();
    processName = parcel.ReadString();
    processType = static_cast<ProcessType>(parcel.ReadInt32());
    extensionType = parcel.ReadInt32();
    renderUid = parcel.ReadInt32();
    accessTokenId = parcel.ReadUint32();
    isTestMode = parcel.ReadBool();
    return true;
}

ProcessData *ProcessData::Unmarshalling(Parcel &parcel)
{
    ProcessData *processData = new (std::nothrow) ProcessData();
    if (processData && !processData->ReadFromParcel(parcel)) {
        delete processData;
        processData = nullptr;
    }
    return processData;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
