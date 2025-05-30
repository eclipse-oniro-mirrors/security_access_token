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
#ifndef FRAMEWORK_CONSTANT_COMMON_H
#define FRAMEWORK_CONSTANT_COMMON_H

#include <algorithm>
#include <iosfwd>

namespace OHOS {
namespace Security {
namespace AccessToken {
class ConstantCommon {
public:
    /**
     * Device id length.
     */
    const static int32_t DEVICE_UUID_LENGTH = 65;
    static constexpr int32_t MINDEVICEIDLEN = 8;
    static constexpr int32_t ENCRYPTLEN = 4;
    static constexpr int32_t ENCRYPTBEGIN = 0;
    static constexpr int32_t ENCRYPTEND = 3;
    static std::string EncryptDevId(std::string deviceId);

    /**
     * GetLocalDeviceId
     */
    static std::string GetLocalDeviceId();

    /**
     * Flag operate
     */
    static bool IsPermOperatedByUser(int32_t flag);
    static bool IsPermOperatedBySystem(int32_t flag);
    static bool IsPermGrantedBySecComp(int32_t flag);
    static uint32_t GetFlagWithoutSpecifiedElement(uint32_t fullFlag, uint32_t removedFlag);
};
}
}
}
#endif