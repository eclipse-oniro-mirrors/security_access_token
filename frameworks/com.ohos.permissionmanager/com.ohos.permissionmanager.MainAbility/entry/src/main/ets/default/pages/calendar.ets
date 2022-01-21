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
import { calendarListItem } from "../common/model/appNameList.ets"
import router from '@system.router'
@Entry
@Component
struct appNamePage {
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
              backBar({title: JSON.stringify($r("app.string.calendar"))})
            }
            Row() {
              Column() {
                Scroll() {
                  appNameItem({
                    calendarListItem: calendarListItem,
                  })
                }
              }
            }.layoutWeight(1)
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
struct appNameItem {
  private calendarListItem: any[]

  build() {
    Row() {
      Column() {
        Row() {
          List() {
            ForEach(this.calendarListItem, (item) => {
              ListItem() {
                Row() {
                  Column() {
                    Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                      Row() {
                        Text(item.name)
                          .fontSize(16)
                          .fontColor($r('app.color.text_color'))
                          .flexGrow(1)
                        Image($r('app.media.rightarrow'))
                          .objectFit(ImageFit.Contain)
                          .height(24)
                          .width(12)
                      }
                      .width('100%')
                      .height(48)
                    }
                    if (item.index !== this.calendarListItem.length) {
                      Row() {
                        Column()
                          .backgroundColor($r('app.color.text_decoration_color'))
                          .width('100%')
                          .height('2vp')
                      }
                    }
                  }.onClick(() => {
                      router.push({
                        uri: 'pages/location-info',
                        params: { routerData: item }
                      })
                  })
                }
              }.padding({ left: 24, right: 24 })
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.margin({ top: 9 }).padding({ left: 24, right: 24 })
      }
      .width('100%')
      .height('100%')
      .backgroundColor($r('app.color.background_color'))
    }
  }
}
