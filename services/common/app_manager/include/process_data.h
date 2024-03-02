/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ACCESS_PROCESS_DATA_H
#define ACCESS_PROCESS_DATA_H

#include <sys/types.h>

#include "parcel.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class AppProcessState {
    APP_STATE_CREATE = 0,
    APP_STATE_READY,
    APP_STATE_FOREGROUND,
    APP_STATE_FOCUS,
    APP_STATE_BACKGROUND,
    APP_STATE_TERMINATED,
    APP_STATE_END,
};

enum class ProcessType {
    NORMAL = 0,
    EXTENSION,
    RENDER,
};

struct ProcessData : public Parcelable {
    /**
     * @brief read this Sequenceable object from a Parcel.
     *
     * @param inParcel Indicates the Parcel object into which the Sequenceable object has been marshaled.
     * @return Returns true if read successed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

    /**
     * @brief Marshals this Sequenceable object into a Parcel.
     *
     * @param outParcel Indicates the Parcel object to which the Sequenceable object will be marshaled.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshals this Sequenceable object from a Parcel.
     *
     * @param inParcel Indicates the Parcel object into which the Sequenceable object has been marshaled.
     */
    static ProcessData *Unmarshalling(Parcel &parcel);

    std::string bundleName;
    int32_t pid = 0;
    int32_t uid = 0;
    int32_t renderUid = -1;
    AppProcessState state;
    bool isContinuousTask = false;
    bool isKeepAlive = false;
    bool isFocused = false;
    int32_t requestProcCode = 0;
    int32_t processChangeReason = 0;
    std::string processName;
    ProcessType processType = ProcessType::NORMAL;
    int32_t extensionType;
    uint32_t accessTokenId = 0;
    bool isTestMode = false;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // ACCESS_PROCESS_DATA_H
