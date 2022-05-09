/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef TOKENSYNC_KIT_TEST_H
#define TOKENSYNC_KIT_TEST_H

#include <gtest/gtest.h>

namespace OHOS {
namespace Security {
static const int32_t BUFF_LEN = 102400;
static const int32_t DELAY_ONE_SECONDS = 5;
static const int32_t DELAY_FIVE_SECONDS = 10;
class TokenLibKitTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    void ResetFile(void);
    void PthreadCloseTrigger(void);
};
} // namespace Security
} // namespace OHOS
#endif // TOKENSYNC_KIT_TEST_H
