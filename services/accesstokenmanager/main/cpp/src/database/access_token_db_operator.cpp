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

#include "access_token_db_operator.h"
#ifdef DYNAMIC_CLOSE_LIBS
#include "rdb_dlopen_manager.h"
#else
#include "access_token_db.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t AccessTokenDbOperator::Modify(const AtmDataType type, const GenericValues& modifyValue,
    const GenericValues& conditionValue)
{
#ifdef DYNAMIC_CLOSE_LIBS
    return RdbDlopenManager::GetInstance()->Modify(type, modifyValue, conditionValue);
#else
    return AccessTokenDb::GetInstance()->Modify(type, modifyValue, conditionValue);
#endif
}

int32_t AccessTokenDbOperator::Find(AtmDataType type, const GenericValues& conditionValue,
    std::vector<GenericValues>& results)
{
#ifdef DYNAMIC_CLOSE_LIBS
    return RdbDlopenManager::GetInstance()->Find(type, conditionValue, results);
#else
    return AccessTokenDb::GetInstance()->Find(type, conditionValue, results);
#endif
}

int32_t AccessTokenDbOperator::DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
#ifdef DYNAMIC_CLOSE_LIBS
    return RdbDlopenManager::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec);
#else
    return AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec);
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
