/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef MOCK_COMMON_TEST_H
#define MOCK_COMMON_TEST_H
namespace OHOS {
enum MockAppStatus {
    INACTIVE = 0,
    ACTIVE_FOREGROUND = 1,
    ACTIVE_BACKGROUND = 2,
};
void SetAppProxyFlag(uint32_t flag);
void SwitchForeOrBackGround(uint32_t tokenId, int32_t flag);
}
#endif // MOCK_COMMON_TEST_H