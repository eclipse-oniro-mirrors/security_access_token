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

#ifndef EL5_FILEKEY_MEMORY_MANAGER_UNITTEST_H
#define EL5_FILEKEY_MEMORY_MANAGER_UNITTEST_H

#include <gtest/gtest.h>
#include <cstdint>

#define private public
#include "el5_filekey_manager_service_ability.h"
#include "el5_filekey_manager_service.h"
#undef private

namespace OHOS {
namespace Security {
namespace AccessToken {
class El5FilekeyMemoryManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp();

    void TearDown() {};
    std::shared_ptr<El5FilekeyManagerServiceAbility> el5FilekeyManagerServiceAbility_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // EL5_FILEKEY_MEMORY_MANAGER_UNITTEST_H
