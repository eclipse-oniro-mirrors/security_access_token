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

#ifndef ACCESS_CONTINUOUS_TASK_CALLBACK_INFO_H
#define ACCESS_CONTINUOUS_TASK_CALLBACK_INFO_H

#include <singleton.h>
#include <string>

#include "parcel.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct ContinuousTaskCallbackInfo : public Parcelable {
    uint32_t typeId_ {0};
    int32_t creatorUid_ {0};
    pid_t creatorPid_ {0};
    std::string abilityName_ {""};
    bool isFromWebview_ {false};
    bool isBatchApi_ {false};
    std::vector<uint32_t> typeIds_ {};
    int32_t abilityId_ {-1};
    uint64_t tokenId_ {0};

    uint64_t GetFullTokenId() const;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static ContinuousTaskCallbackInfo *Unmarshalling(Parcel &parcel);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_CONTINUOUS_TASK_CALLBACK_INFO_H
