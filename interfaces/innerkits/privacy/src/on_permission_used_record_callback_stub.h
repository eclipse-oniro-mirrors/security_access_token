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

#ifndef ON_PERMISSION_USED_RECORD_CALLBACK_STUB_H
#define ON_PERMISSION_USED_RECORD_CALLBACK_STUB_H

#include "on_permission_used_record_callback.h"

#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class OnPermissionUsedRecordCallbackStub : public IRemoteStub<OnPermissionUsedRecordCallback> {
public:
    OnPermissionUsedRecordCallbackStub() = default;
    virtual ~OnPermissionUsedRecordCallbackStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ON_PERMISSION_USED_RECORD_CALLBACK_STUB_H
