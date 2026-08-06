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

#include "app_state_data.h"

#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool AppStateData::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(bundleName) && parcel.WriteInt32(uid) && parcel.WriteInt32(state) &&
        parcel.WriteInt32(pid) && parcel.WriteUint32(accessTokenId) && parcel.WriteBool(isFocused) &&
        parcel.WriteInt32(extensionType) && parcel.WriteInt32Vector(renderPids) &&
        parcel.WriteString(callerBundleName) && parcel.WriteBool(isSplitScreenMode) && parcel.WriteInt32(callerUid) &&
        parcel.WriteBool(isFloatingWindowMode) && parcel.WriteInt32(appIndex) && parcel.WriteBool(isPreloadModule) &&
        parcel.WriteBool(isFromWindowFocusChanged) && parcel.WriteInt32(preloadMode) &&
        parcel.WriteInt32(byCallStatus);
}

AppStateData *AppStateData::Unmarshalling(Parcel &parcel)
{
    AppStateData *appStateData = new (std::nothrow) AppStateData();
    if (appStateData == nullptr) {
        return nullptr;
    }
    RELEASE_IF_FALSE(parcel.ReadString(appStateData->bundleName), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->uid), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->state), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->pid), appStateData);
    RELEASE_IF_FALSE(parcel.ReadUint32(appStateData->accessTokenId), appStateData);
    RELEASE_IF_FALSE(parcel.ReadBool(appStateData->isFocused), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->extensionType), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32Vector(&appStateData->renderPids), appStateData);
    RELEASE_IF_FALSE(parcel.ReadString(appStateData->callerBundleName), appStateData);
    RELEASE_IF_FALSE(parcel.ReadBool(appStateData->isSplitScreenMode), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->callerUid), appStateData);
    RELEASE_IF_FALSE(parcel.ReadBool(appStateData->isFloatingWindowMode), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->appIndex), appStateData);
    RELEASE_IF_FALSE(parcel.ReadBool(appStateData->isPreloadModule), appStateData);
    RELEASE_IF_FALSE(parcel.ReadBool(appStateData->isFromWindowFocusChanged), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->preloadMode), appStateData);
    RELEASE_IF_FALSE(parcel.ReadInt32(appStateData->byCallStatus), appStateData);
    return appStateData;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
