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
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "data_validator.h"
#include "constant_common.h"
#include "tokenid_attributes.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
}
AccessTokenRemoteTokenManager::AccessTokenRemoteTokenManager()
{}

AccessTokenRemoteTokenManager::~AccessTokenRemoteTokenManager()
{
}

AccessTokenRemoteTokenManager& AccessTokenRemoteTokenManager::GetInstance()
{
    static AccessTokenRemoteTokenManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AccessTokenRemoteTokenManager* tmp = new (std::nothrow) AccessTokenRemoteTokenManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

AccessTokenID AccessTokenRemoteTokenManager::MapRemoteDeviceTokenToLocal(const std::string& deviceID,
    AccessTokenID remoteID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID) || !DataValidator::IsTokenIDValid(remoteID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s or token %{public}x is invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return 0;
    }
    ATokenTypeEnum tokeType = TokenIDAttributes::GetTokenIdTypeEnum(remoteID);
    if ((tokeType <= TOKEN_INVALID) || (tokeType >= TOKEN_TYPE_BUTT)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}x type is invalid.", remoteID);
        return 0;
    }
    int32_t dlpFlag = TokenIDAttributes::GetTokenIdDlpFlag(remoteID);
    int32_t cloneFlag = TokenIDAttributes::GetTokenIdCloneFlag(remoteID);

    AccessTokenID mapID = 0;
    std::unique_lock<std::shared_mutex> infoGuard(this->remoteDeviceLock_);
    std::map<AccessTokenID, AccessTokenID>* mapPtr = nullptr;
    if (remoteDeviceMap_.count(deviceID) > 0) {
        AccessTokenRemoteDevice& device = remoteDeviceMap_[deviceID];
        if (device.MappingTokenIDPairMap_.count(remoteID) > 0) {
            mapID = device.MappingTokenIDPairMap_[remoteID];
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Device %{public}s token %{public}x has already mapped, map tokenID is %{public}x.",
                ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
            return mapID;
        }
        mapPtr = &device.MappingTokenIDPairMap_;
    } else {
        AccessTokenRemoteDevice device;
        device.deviceID_ = deviceID;
        remoteDeviceMap_[deviceID] = device;
        mapPtr = &remoteDeviceMap_[deviceID].MappingTokenIDPairMap_;
    }

    mapID = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(tokeType, dlpFlag, cloneFlag);
    if (mapID == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}x map local Token failed.",
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s is valid.", ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::shared_lock<std::shared_mutex> infoGuard(this->remoteDeviceLock_);
    if (remoteDeviceMap_.count(deviceID) < 1) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s has not mapping.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_DEVICE_NOT_EXIST;
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s or token %{public}x is invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return 0;
    }

    std::shared_lock<std::shared_mutex> infoGuard(this->remoteDeviceLock_);
    if (remoteDeviceMap_.count(deviceID) < 1 ||
        remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.count(remoteID) < 1) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s has not mapping.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return 0;
    }

    return remoteDeviceMap_[deviceID].MappingTokenIDPairMap_[remoteID];
}

int AccessTokenRemoteTokenManager::RemoveDeviceMappingTokenID(const std::string& deviceID,
    AccessTokenID remoteID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID) || !DataValidator::IsTokenIDValid(remoteID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s or token %{public}x is invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return ERR_PARAM_INVALID;
    }

    std::unique_lock<std::shared_mutex> infoGuard(this->remoteDeviceLock_);
    if (remoteDeviceMap_.count(deviceID) < 1 ||
        remoteDeviceMap_[deviceID].MappingTokenIDPairMap_.count(remoteID) < 1) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s has not mapping.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return ERR_TOKEN_MAP_FAILED;
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
