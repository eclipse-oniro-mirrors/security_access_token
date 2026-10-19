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
#include "bundle_infos_rawdata_helper.h"

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
    const HapVerifyResultInfo& resultInfo,
    CheckHapSignResultRawdata& rawData)
{
    MessageParcel parcel;
    parcel.SetMaxCapacity(MAX_BUNDLE_INFOS_RAW_DATA_SIZE);

    RETURN_IF_FALSE(parcel.WriteInt32(realResult));
    RETURN_IF_FALSE(parcel.WriteInt32(sessionId));

    RETURN_IF_FALSE(BundleInfosRawdataHelper::WriteBundleInfosToParcel(bundleInfos, parcel));

    RETURN_IF_FALSE(parcel.WriteUint32(resultInfo.index));
    RETURN_IF_FALSE(parcel.WriteInt32(resultInfo.errorCode));

    rawData.size = static_cast<uint32_t>(parcel.GetDataSize());
    RETURN_IF_FALSE(rawData.size <= MAX_BUNDLE_INFOS_RAW_DATA_SIZE);

    void* bufferPtr = reinterpret_cast<void *>(parcel.GetData());
    return rawData.RawDataCpy(bufferPtr) == 0;
}

bool CheckHapSignResultRawdataHelper::ReadFromRawData(
    const CheckHapSignResultRawdata& rawData,
    int32_t& realResult,
    int32_t& sessionId,
    std::vector<TrustedBundleInfo>& bundleInfos,
    HapVerifyResultInfo& resultInfo)
{
    if ((rawData.data == nullptr) || (rawData.size == 0)) {
        return false;
    }

    MessageParcel parcel;
    parcel.SetMaxCapacity(MAX_BUNDLE_INFOS_RAW_DATA_SIZE);

    RETURN_IF_FALSE(parcel.WriteBuffer(rawData.data, rawData.size));

    RETURN_IF_FALSE(parcel.ReadInt32(realResult));
    RETURN_IF_FALSE(parcel.ReadInt32(sessionId));

    RETURN_IF_FALSE(BundleInfosRawdataHelper::ReadBundleInfosFromParcel(parcel, bundleInfos));

    RETURN_IF_FALSE(parcel.ReadUint32(resultInfo.index));
    RETURN_IF_FALSE(parcel.ReadInt32(resultInfo.errorCode));

    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
