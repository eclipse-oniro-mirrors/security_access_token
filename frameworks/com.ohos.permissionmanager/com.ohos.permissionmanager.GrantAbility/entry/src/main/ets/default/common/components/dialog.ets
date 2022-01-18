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

import { dialogData } from "../model/dialogDataList.ets"

@Extend(Button) function customizeButton() {
  .backgroundColor($r('app.color.default_background_color'))
  .fontColor($r('app.color.button_color'))
}

@CustomDialog
export struct spaceDialog {
  controller: CustomDialogController
  cancel: () => void
  confirm: () => void

  build() {
    Column() {
      Image($r('app.media.ic_nearby'))
        .width(24)
        .height(24)
        .margin({
          top: 24
        })
      Column() {
        Row() {
          Flex({ justifyContent: FlexAlign.Start }) {
            Text('是否允许“XX”查找、连接附近设备？').fontSize(16)
              .margin({
                top: 16,
                left: 24
              })
          }
        }
        Row() {
          Flex({ justifyContent: FlexAlign.Start }) {
            Text('用于XXXX。').fontSize(14)
              .fontColor($r('app.color.secondary_font_color'))
              .margin({
                top: 2,
                left: 24
              })
          }
        }
      }
      Row() {
        Flex({ justifyContent: FlexAlign.SpaceAround }) {
          Button('禁止')
            .fontSize(16)
            .onClick(() => {
              this.controller.close()
              this.cancel()
            }).customizeButton()
          Text('|').fontSize(30).fontColor($r('app.color.divider_color'))
          Button('允许')
            .fontSize(16)
            .onClick(() => {
              this.controller.close()
              this.confirm()
            }).customizeButton()
        }.margin({
          top: 8
        })
      }
    }
    .backgroundColor($r('app.color.default_background_color'))
    .borderRadius(24)
    .height(170)
    .width(336)
  }
}

@CustomDialog
export struct privacyDialog {
  @Prop count: number
  controller: CustomDialogController
  cancel: () => void
  confirm: () => void

  build() {
    Column() {
      if (this.count < dialogData.length) {
        Image(dialogData[this.count].icon)
          .width(24)
          .height(24)
          .margin({
            top: 24
          })
        Text(`${this.count + 1} / ${dialogData.length}`)
          .fontSize(14)
          .fontColor($r('app.color.secondary_font_color'))
          .margin({
            top: 2
          })
        Column() {
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text(dialogData[this.count].message1).fontSize(16)
                .margin({
                  top: 16,
                  left: 24
                })
            }
          }
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text(dialogData[this.count].message2).fontSize(14)
                .fontColor($r('app.color.secondary_font_color'))
                .margin({
                  top: 2,
                  left: 24
                })
            }
          }
        }
      }
      Row() {
        Flex({ justifyContent: FlexAlign.SpaceAround }) {
          Button('禁止')
            .fontSize(16)
            .onClick(() => {
              this.cancel()
              if (this.count === dialogData.length) {
                this.controller.close()
              }
            }).customizeButton()
          Text('|').fontSize(30).fontColor($r('app.color.divider_color'))
          Button('允许')
            .fontSize(16)
            .onClick(() => {
              this.confirm()
              if (this.count === dialogData.length) {
                this.controller.close()
              }
            }).customizeButton()
        }.margin({
          top: 8
        })
      }
    }
    .backgroundColor($r('app.color.default_background_color'))
    .borderRadius(24)
    .height(186)
    .width(336)
  }
}
