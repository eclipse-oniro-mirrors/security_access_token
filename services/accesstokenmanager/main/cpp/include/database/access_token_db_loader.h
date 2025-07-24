/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ACCESS_TOKEN_DB_LOADER_H
#define ACCESS_TOKEN_DB_LOADER_H

#include "atm_data_type.h"
#include "generic_values.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenDbLoaderInterface {
public:
    AccessTokenDbLoaderInterface() {}
    virtual ~AccessTokenDbLoaderInterface() {}

    virtual void InitRdbHelper() = 0;
    virtual int32_t Modify(const AtmDataType type, const GenericValues& modifyValue,
        const GenericValues& conditionValue) = 0;
    virtual int32_t Find(AtmDataType type, const GenericValues& conditionValue,
        std::vector<GenericValues>& results) = 0;
    virtual int32_t DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
        const std::vector<AddInfo>& addInfoVec) = 0;
    virtual bool DestroyRdbHelper() = 0;
};

class AccessTokenDbLoader final: public AccessTokenDbLoaderInterface {
public:
    AccessTokenDbLoader();
    virtual ~AccessTokenDbLoader();

    void InitRdbHelper() override;
    int32_t Modify(const AtmDataType type, const GenericValues& modifyValue,
        const GenericValues& conditionValue) override;
    int32_t Find(AtmDataType type, const GenericValues& conditionValue,
        std::vector<GenericValues>& results) override;
    int32_t DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
        const std::vector<AddInfo>& addInfoVec) override;
    bool DestroyRdbHelper() override;
};

#ifdef __cplusplus
extern "C" {
#endif
    void* Create();
    void Destroy(void* loaderPtr);
#ifdef __cplusplus
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_DB_LOADER_H
