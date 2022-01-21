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
import { permissionGroups, groups } from "../model/permissionGroup.ets"
import bundle from '@ohos.bundle';

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
      Image($r('app.media.ic_ssensor'))
        .width(24)
        .height(24)
        .margin({
          top: 24
        })
      Column() {
        Row() {
          Flex({ justifyContent: FlexAlign.Start }) {
            Text('是否允许“XX”使用身体传感器？').fontSize(16)
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
  @State permissionList: Array<any> = []

  build() {
    Column() {
      if (this.count < this.permissionList.length) {
        Image(dialogData[this.count].icon)
          .width(24)
          .height(24)
          .margin({
            top: 24
          })
        Text(`${this.count + 1} / ${this.permissionList.length}`)
          .fontSize(14)
          .fontColor($r('app.color.secondary_font_color'))
          .margin({
            top: 2
          })
        Column() {
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text("是否允许该应用访问" + this.current().groupName).fontSize(16)
                .margin({
                  top: 16,
                  left: 24
                })
            }
          }
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text("用于" + this.current().description).fontSize(14)
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
              setTimeout(() => {
                if (this.count === this.permissionList.length) {
                  this.controller.close()
                }
              }, 1)
            }).customizeButton()
          Text('|').fontSize(30).fontColor($r('app.color.divider_color'))
          Button('允许')
            .fontSize(16)
            .onClick(() => {
              this.confirm()
              setTimeout(() => {
                if (this.count === this.permissionList.length) {
                  this.controller.close()
                }
              }, 1)
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
  current() {
    var current = this.permissionList[this.count]
    var permission = permissionGroups.filter(item => item.name == current)
    var group = groups.filter(item => item.name == permission[0].group)
    return group[0]
  }

  aboutToAppear() {
    bundle.getApplicationInfo('com.example.myapplication', 0x00000000, 0).then(res => {
      this.permissionList = res.permissions
    })
  }
}
