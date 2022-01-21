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

import router from '@system.router'

@Component
export struct backBar {
  @Prop title: string

  build() {
    Column() {
      Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
        if (this.title == JSON.stringify($r('app.string.privacy'))) {
          Text($r('app.string.privacy'))
            .fontColor($r('app.color.title_text_color'))
            .fontSize("20fp")
            .margin({
              left: "15vp",
              right: "24vp",
              top: "17vp"
            })
        } else {
          Image($r('app.media.left'))
            .objectFit(ImageFit.Contain)
            .height(24)
            .width(24)
            .margin({
              top: "17vp",
              left: "24vp",
              right: "15vp"
            })
            .onClick(() => {
              router.back()
            })
          Text(JSON.parse(this.title))
            .fontColor($r('app.color.title_text_color'))
            .fontSize(20)
            .flexGrow(1)
            .margin({ top: "17vp" })
          if (false) {
            Image($r('app.media.record'))
              .objectFit(ImageFit.Contain)
              .height(25)
              .width(25)
              .margin({
                right: "15vp",
                top: "17vp"
              })
              .onClick(() => {
                router.push({ uri: "pages/permission-access-record" })
              })
          }
        }
      }
    }
    .height(56)
    .constraintSize({ minHeight: "56vp" })
    .alignItems(HorizontalAlign.Start)
    .backgroundColor($r('app.color.background_color'))
  }
}