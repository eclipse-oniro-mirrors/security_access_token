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

#include "check_hap_sign_result_rawdata_helper.h"

#include "ipc_skeleton.h"
#include "parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

bool CheckHapSignResultRawdataHelper::WriteToRawData(
    int32_t realResult,
    int32_t sessionId,
    const std::vector<TrustedBundleInfo>& bundleInfos,
    CheckHapSignResultRawdata& rawData)
{
    MessageParcel parcel;
    parcel.SetMaxCapacity(MAX_BUNDLE_INFOS_RAW_DATA_SIZE);
    
    RETURN_IF_FALSE(parcel.WriteInt32(realResult));
    RETURN_IF_FALSE(parcel.WriteInt32(sessionId));
    
    uint32_t count = static_cast<uint32_t>(bundleInfos.size());
    RETURN_IF_FALSE(parcel.WriteUint32(count));
    
    for (const auto& info : bundleInfos) {
        RETURN_IF_FALSE(parcel.WriteString(info.profileData.provisionRaw));
        RETURN_IF_FALSE(parcel.WriteInt32(info.profileData.profileBlockLength));
        RETURN_IF_FALSE(parcel.WriteUInt8Vector(info.profileData.profileBlock));
        RETURN_IF_FALSE(parcel.WriteString(info.profileData.appId));
        RETURN_IF_FALSE(parcel.WriteString(info.profileData.fingerprint));
        RETURN_IF_FALSE(parcel.WriteString(info.profileData.organization));
        RETURN_IF_FALSE(parcel.WriteBool(info.profileData.isOpenHarmony));
        RETURN_IF_FALSE(parcel.WriteBool(info.profileData.isEnterpriseResigned));
        RETURN_IF_FALSE(parcel.WriteString(info.moduleInfo));
        RETURN_IF_FALSE(parcel.WriteString(info.sharedFiles));
    }
    
    size_t bufferSize = parcel.GetDataSize();
    RETURN_IF_FALSE(bufferSize <= MAX_BUNDLE_INFOS_RAW_DATA_SIZE);

    void* bufferPtr = reinterpret_cast<void *>(parcel.GetData());
    rawData.size = static_cast<uint32_t>(bufferSize);
    return rawData.RawDataCpy(bufferPtr) == 0;
}

bool CheckHapSignResultRawdataHelper::ReadFromRawData(
    const CheckHapSignResultRawdata& rawData,
    int32_t& realResult,
    int32_t& sessionId,
    std::vector<TrustedBundleInfo>& bundleInfos)
{
    if ((rawData.data == nullptr) || (rawData.size == 0)) {
        return false;
    }
    
    MessageParcel parcel;
    parcel.SetMaxCapacity(MAX_BUNDLE_INFOS_RAW_DATA_SIZE);
    
    RETURN_IF_FALSE(parcel.WriteBuffer(rawData.data, rawData.size));
    
    RETURN_IF_FALSE(parcel.ReadInt32(realResult));
    RETURN_IF_FALSE(parcel.ReadInt32(sessionId));
    
    uint32_t count;
    RETURN_IF_FALSE(parcel.ReadUint32(count));
    if (count > MAX_BUNDLE_INFO_SIZE) {
        return false;
    }
    
    for (uint32_t i = 0; i < count; ++i) {
        TrustedBundleInfo info;
        
        RETURN_IF_FALSE(parcel.ReadString(info.profileData.provisionRaw));
        RETURN_IF_FALSE(parcel.ReadInt32(info.profileData.profileBlockLength));
        RETURN_IF_FALSE(parcel.ReadUInt8Vector(&info.profileData.profileBlock));
        RETURN_IF_FALSE(parcel.ReadString(info.profileData.appId));
        RETURN_IF_FALSE(parcel.ReadString(info.profileData.fingerprint));
        RETURN_IF_FALSE(parcel.ReadString(info.profileData.organization));
        RETURN_IF_FALSE(parcel.ReadBool(info.profileData.isOpenHarmony));
        RETURN_IF_FALSE(parcel.ReadBool(info.profileData.isEnterpriseResigned));
        RETURN_IF_FALSE(parcel.ReadString(info.moduleInfo));
        RETURN_IF_FALSE(parcel.ReadString(info.sharedFiles));
        
        bundleInfos.push_back(info);
    }
    
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS