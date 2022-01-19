/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

@Component
export struct titleBar {
  build() {
    Column() {
      Text($r('app.string.settings'))
        .fontColor($r('app.color.title_text_color'))
        .fontSize("24fp")
        .margin({
          left: "14vp",
          right: "24vp",
          top: "12vp"
        })
    }
    .useSizeType({
      xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
      md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
    })
    .width('40%')
    .height(56)
    .constraintSize({ minHeight: "56vp" })
    .alignItems(HorizontalAlign.Start)
    .backgroundColor($r('app.color.background_color'))
  }
}