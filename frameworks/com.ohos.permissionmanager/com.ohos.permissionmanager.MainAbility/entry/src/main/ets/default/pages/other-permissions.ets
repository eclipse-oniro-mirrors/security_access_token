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

import { backBar } from "../common/components/backBar.ets"
import { otherPermissionsListItem } from "../common/model/otherPermissionsList.ets"
import router from '@system.router'
@Entry
@Component
struct permissionsPage {
  build() {
    GridContainer({ gutter: 0 }) {
      Row() {
        Row()
          .useSizeType({
            xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
            md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
          })
          .height("100%")
        Row() {
          Column() {
            Row() {
              backBar({title: JSON.stringify($r("app.string.other_permissions"))})
            }
            Row() {
              Column() {
                Scroll() {
                  otherPermissionsItem({
                    otherPermissionsListItem: otherPermissionsListItem
                  })
                }
              }.width("100%")
            }
            .layoutWeight(1)
          }
        }
        .useSizeType({
          xs: { span: 1, offset: 1 }, sm: { span: 2, offset: 1 },
          md: { span: 6, offset: 1 }, lg: { span: 8, offset: 2 }
        })
        .height("100%")
        Row()
          .useSizeType({
            xs: { span: 1, offset: 2 }, sm: { span: 1, offset: 3 },
            md: { span: 1, offset: 7 }, lg: { span: 2, offset: 10 }
          })
          .height("100%")
      }
      .height('100%')
    }
  }
}

@Component
struct otherPermissionsItem {
  private otherPermissionsListItem: any[]
  build() {
    Row() {
      Column() {
        List() {
          ForEach(this.otherPermissionsListItem, (item) => {
            ListItem() {
              Column() {
                Row() {
                  Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                    Row() {
                      Text(item.name)
                        .fontSize(16)
                        .fontColor($r('app.color.text_color'))
                        .flexGrow(1)
                      Image(item.icon)
                        .objectFit(ImageFit.Contain)
                        .height(24)
                        .width(12)
                    }.backgroundColor($r('app.color.default_background_color'))
                    .width('100%')
                    .height('48')
                  }
                }
                if (item.index !== this.otherPermissionsListItem.length) {
                  Row() {
                    Column()
                      .backgroundColor($r('app.color.text_decoration_color'))
                      .width('100%')
                      .height('2vp')
                  }
                }
              }
              .onClick(() => {
              })
            }
            .padding({ left: 12,right: 12 })
            .margin({ top: 1 })
          }, item => item.toString())
        }
        .margin({top:8})
        .borderRadius(24)
        .backgroundColor($r('app.color.default_background_color'))
        .padding({ left: 12, right: 12, top: 3, bottom: 4 })
      }
      .padding({ left: 37, right: 37 })
      .width('100%')
      .height('100%')
      .backgroundColor($r('app.color.background_color'))
    }
  }
}