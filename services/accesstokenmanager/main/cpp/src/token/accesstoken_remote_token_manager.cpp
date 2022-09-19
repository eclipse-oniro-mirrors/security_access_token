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

#include "accesstoken_remote_token_manager.h"

#include "accesstoken_id_manager.h"
#include "accesstoken_log.h"
#include "data_validator.h"
#include "constant_common.h"
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenRemoteTokenManager"};
}
AccessTokenRemoteTokenManager::AccessTokenRemoteTokenManager()
{}

AccessTokenRemoteTokenManager::~AccessTokenRemoteTokenManager()
{
}

AccessTokenRemoteTokenManager& AccessTokenRemoteTokenManager::GetInstance()
{
    static AccessTokenRemoteTokenManager instance;
    return instance;
}

AccessTokenID AccessTokenRemoteTokenManager::MapRemoteDeviceTokenToLocal(const std::string& deviceID,
    AccessTokenID remoteID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID) || !DataValidator::IsTokenIDValid(remoteID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s or token %{public}x is invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return 0;
    }
    ATokenTypeEnum tokeType = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(remoteID);
    if ((tokeType <= TOKEN_INVALID) || (tokeType >= TOKEN_TYPE_BUTT)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "token %{public}x type is invalid.", remoteID);
        return 0;
    }
    int dlpType = AccessTokenIDManager::GetInstance().GetTokenIdDlpFlag(remoteID);

    AccessTokenID mapID = 0;
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->remoteDeviceLock_);
    std::map<AccessTokenID, AccessTokenID>* mapPtr = nullptr;
    if (remoteDeviceMap_.count(deviceID) > 0) {
        AccessTokenRemoteDevice& device = remoteDeviceMap_[deviceID];
        if (device.MappingTokenIDPairMap_.count(remoteID) > 0) {
            mapID = device.MappingTokenIDPairMap_[remoteID];
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "device %{public}s token %{public}x has already mapped, maptokenID is %{public}x.",
                ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
            return mapID;
        }
        mapPtr = &device.MappingTokenIDPairMap_;
    } else {
        AccessTokenRemoteDevice device;
        device.DeviceID_ = deviceID;
        remoteDeviceMap_[deviceID] = device;
        mapPtr = &remoteDeviceMap_[deviceID].MappingTokenIDPairMap_;
    }

    mapID = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(tokeType, dlpType);
    if (mapID == 0) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "device %{public}s token %{public}x map local Token failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return 0;
    }
    mapPtr->insert(std::pair<AccessTokenID, AccessTokenID>(remoteID, mapID));
    return mapID;
}

int AccessTokenRemoteTokenManager::GetDeviceAllRemoteTokenID(const std::string& deviceID,
    std::vector<AccessTokenID>& remoteIDs)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s is valid.", ConstantCommon::EncryptDevId(deviceID).c_str());
        return RET_FAILED;
    }
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->remoteDeviceLock_);
    if (remoteDeviceMap_.count(deviceID) < 1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s has not mapping.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return RET_FAILED;
    }

    std::transform(remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.begin(),
        remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.end(),
        std::back_inserter(remoteIDs), [](const auto& mapEntry) {
            return mapEntry.first;
        });
    return RET_SUCCESS;
}

AccessTokenID AccessTokenRemoteTokenManager::GetDeviceMappingTokenID(const std::string& deviceID,
    AccessTokenID remoteID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID) || !DataValidator::IsTokenIDValid(remoteID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s or token %{public}x is invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return 0;
    }

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->remoteDeviceLock_);
    if (remoteDeviceMap_.count(deviceID) < 1 ||
        remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.count(remoteID) < 1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s has not mapping.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return 0;
    }

    return remoteDeviceMap_[deviceID].MappingTokenIDPairMap_[remoteID];
}

int AccessTokenRemoteTokenManager::RemoveDeviceMappingTokenID(const std::string& deviceID,
    AccessTokenID remoteID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID) || !DataValidator::IsTokenIDValid(remoteID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s or token %{public}x is invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return RET_FAILED;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->remoteDeviceLock_);
    if (remoteDeviceMap_.count(deviceID) < 1 ||
        remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.count(remoteID) < 1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "device %{public}s has not mapping.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return RET_FAILED;
    }

    AccessTokenID mapID = remoteDeviceMap_[deviceID].MappingTokenIDPairMap_[remoteID];
    AccessTokenIDManager::GetInstance().ReleaseTokenId(mapID);

    remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.erase(remoteID);

    if (remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.empty()) {
        remoteDeviceMap_.erase(deviceID);
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
