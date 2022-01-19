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

import { titleBar } from "../common/components/titleBar.ets"
import { categoryPage } from "../common/components/category.ets"
import { backBar } from "../common/components/backBar.ets"
import { calendarListItem, dynamicListItem } from "../common/model/appNameList.ets"
import router from '@system.router'
@Entry
@Component
struct appNamePage {
  private routerData = router.getParams().routerData
  build() {
    Flex({ justifyContent: FlexAlign.Center }) {
      Column() {
        Row() {
          //        titleBar()
          backBar({ title: JSON.stringify(this.routerData.name) })
        }
        Row() {
          //        categoryPage()
          Column() {
            Scroll() {
              appNameItem({
                calendarListItem: calendarListItem,
                dynamicListItem: dynamicListItem
              })
            }
          }
        }.layoutWeight(1).width(360)
      }
    }
  }
}

@Component
struct appNameItem {
  private calendarListItem: any[]
  private dynamicListItem: any[]

  build() {
    Row() {
      Column() {
        Row() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Text($r('app.string.calendar'))
              .fontSize(14)
              .margin({ top: 19.5, left: 48 })
          }
        }
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
                        Toggle({ type: ToggleType.Switch, isOn: true })
                          .selectedColor($r('app.color.toggle_color'))
                          .width(36)
                          .height(20)
                          .onChange((isOn: boolean) => {
                          })
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
                  })
                }
              }.padding({ left: 24, right: 24 })
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.margin({ top: 9 }).padding({ left: 24, right: 24 })
        Row() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Text('xxx')
              .fontSize(14)
              .margin({ top: 19.5, left: 48 })
          }
        }
        Row() {
          List() {
            ForEach(this.dynamicListItem, (item) => {
              ListItem() {
                Row() {
                  Column() {
                    Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                      Row() {
                        Text(item.name)
                          .fontSize(16)
                          .fontColor($r('app.color.text_color'))
                          .flexGrow(1)
                        Toggle({ type: ToggleType.Switch, isOn: true })
                          .selectedColor($r('app.color.toggle_color'))
                          .width(36)
                          .height(20)
                          .onChange((isOn: boolean) => {
                          })
                      }
                      .width('100%')
                      .height(48)
                    }
                    if (item.index !== this.dynamicListItem.length) {
                      Row() {
                        Column()
                          .backgroundColor($r('app.color.text_decoration_color'))
                          .width('100%')
                          .height('2vp')
                      }
                    }
                  }.onClick(() => {
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
    }.useSizeType({
      xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
      md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
    })
  }
}
