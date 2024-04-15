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
#include <gtest/gtest.h>

#include "ability_context_impl.h"
#include "token_setproc.h"
#include "window.h"
#include "window_scene.h"
#include "wm_common.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {

static const int32_t RET_OK = 0;
static inline float g_virtualPixelRatio = 1.0;
static inline std::shared_ptr<AbilityRuntime::AbilityContext> g_abilityContext_ = nullptr;
}

class CreateCameraWindowTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void CreateCameraWindowTest::SetUpTestCase() {}

void CreateCameraWindowTest::TearDownTestCase() {}
void CreateCameraWindowTest::SetUp() {}
void CreateCameraWindowTest::TearDown() {}

static sptr<Rosen::WindowScene> CreateWindowScene()
{
    sptr<Rosen::IWindowLifeCycle> listener = nullptr;
    g_abilityContext_ = std::make_shared<AbilityRuntime::AbilityContextImpl>();

    sptr<Rosen::WindowScene> scene = new Rosen::WindowScene();
    scene->Init(0, g_abilityContext_, listener);
    return scene;
}

static sptr<Rosen::Window> CreateAppFloatingWindow(Rosen::WindowType type, Rosen::Rect rect, std::string name = "")
{
    sptr<Rosen::WindowOption> option = new Rosen::WindowOption();
    option->SetWindowType(type);
    option->SetWindowRect(rect);

    static int cnt = 0;
    std::string winName = (name == "") ? "FloatingWindowTest" + std::to_string(cnt++) : name;

    return Rosen::Window::Create(winName, option, g_abilityContext_);
}

static inline Rosen::Rect GetRectWithVpr(int32_t x, int32_t y, uint32_t w, uint32_t h)
{
    auto vpr = g_virtualPixelRatio;
    return {x, y, static_cast<uint32_t>(w * vpr), static_cast<uint32_t>(h * vpr)};
}

/**
 * @tc.name: CreateCameraFloatWindowTest
 * @tc.desc: Create camera float window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CreateCameraWindowTest, CreateCameraFloatWindowTest, TestSize.Level1)
{
    uint32_t tokenId = GetSelfTokenID();
    GTEST_LOG_(INFO) << "CreateCameraFloatWindowTest begin, tokenId: " << tokenId << std::endl;

    sptr<Rosen::WindowScene> scene = CreateWindowScene();
    ASSERT_NE(scene, nullptr);

    Rosen::Rect fltWindRect = GetRectWithVpr(0, 0, 400, 600);
    sptr<Rosen::Window> fltWin = CreateAppFloatingWindow(Rosen::WindowType::WINDOW_TYPE_FLOAT_CAMERA, fltWindRect);
    ASSERT_NE(fltWin, nullptr);

    GTEST_LOG_(INFO) << "1. Create camera float window\n" << std::endl;

    int32_t ret = static_cast<int32_t>(scene->GoForeground());
    ASSERT_EQ(ret, RET_OK);

    ret = static_cast<int32_t>(fltWin->Show());
    ASSERT_EQ(ret, RET_OK);

    GTEST_LOG_(INFO) << "2. GoForeground\n" << std::endl;

    usleep(500000); // 500000us = 0.5s

    ret = static_cast<int32_t>(fltWin->Hide());
    ASSERT_EQ(ret, RET_OK);

    GTEST_LOG_(INFO) << "3. Hide window\n" << std::endl;

    usleep(500000); // 500000us = 0.5s

    ret = static_cast<int32_t>(fltWin->Destroy());
    ASSERT_EQ(ret, RET_OK);

    GTEST_LOG_(INFO) << "4. Destroy window\n" << std::endl;

    ret = static_cast<int32_t>(scene->GoDestroy());
    ASSERT_EQ(ret, RET_OK);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
