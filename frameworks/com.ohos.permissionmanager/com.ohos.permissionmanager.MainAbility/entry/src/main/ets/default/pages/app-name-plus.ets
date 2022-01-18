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
import { allowedListItem, bannedListItem } from "../common/model/appNameList.ets"
import router from '@system.router'

@Entry
@Component
struct appNamePlusPage {
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
                 allowedListItem: allowedListItem,
                 bannedListItem: bannedListItem,
//                 buttonListItem: buttonListItem
               })
             }
           }.width('100%')
         }.layoutWeight(1).width(360)
       }
     }
  }
}

@Component
struct appNameItem {
  private allowedListItem: any[]
  private bannedListItem: any[]
//  private buttonListItem: any[]
  @State text: string = ''
  @State fontColor: string = ''

  build() {
    Row() {
      Column() {
        Row() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Text($r('app.string.allowed'))
              .fontSize(14)
              .margin({ top: 19.5, left: 48 })
          }
        }
        Row() {
          List() {
            ForEach(this.allowedListItem, (item) => {
              ListItem() {
                Row() {
                  Column() {
                    Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                      Row() {
                        Column() {
                          if(item.permission != ''){
                            Row() {
                              Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                                Text(item.name)
                                  .fontSize(16)
                                  .fontColor($r('app.color.text_color'))
                              }
                            }.margin({ top: 8 })
                            Row() {
                              Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                                Text(item.permission)
                                  .fontSize(14)
                                  .fontColor($r('app.color.icon_color'))
                              }
                            }.margin({ bottom: 8 })
                          }else{
                            Row() {
                              Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                                Text(item.name)
                                  .fontSize(16)
                                  .fontColor($r('app.color.text_color'))
                              }.margin({ top: 8, bottom: 8 })
                            }.height('100%')
                          }

                        }.flexGrow(1).constraintSize({ minHeight: "48vp" })
                        Image($r('app.media.rightarrow'))
                          .objectFit(ImageFit.Contain)
                          .height(24)
                          .width(12)
                      }
                      .width('100%')
                      .height(48)
                    }
                    if (item.index !== this.allowedListItem.length) {
                      Row() {
                        Column()
                          .backgroundColor($r('app.color.text_decoration_color'))
                          .width('100%')
                          .height('2vp')
                      }
                    }
                  }.onClick(() => {
                    router.push({
                      uri: 'pages/app-name',
                      params: { routerData: item }
                    })
                  })
                }
              }.padding({ left: 24, right: 24 })
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.margin({ top: 9 }).padding({ left: 24, right: 24 })
        Row() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Text($r('app.string.banned'))
              .fontSize(14)
              .margin({ top: 19.5, left: 48 })
          }
        }
        Row() {
          List() {
            ForEach(this.bannedListItem, (item) => {
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
                    if (item.index !== this.bannedListItem.length) {
                      Row() {
                        Column()
                          .backgroundColor($r('app.color.text_decoration_color'))
                          .width('100%')
                          .height('2vp')
                      }
                    }
                  }.onClick(() => {
                    router.push({
                      uri: 'pages/app-name',
                      params: { routerData: item }
                    })
                  })
                }
              }.padding({ left: 24, right: 24 })
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.margin({ top: 9 }).padding({ left: 24, right: 24 })
        Row() {
//          if(this.buttonListItem[0]['name'] !== 'disabled' ) {
//            Button('查看所有权限', { type: ButtonType.Capsule, stateEffect: false })
//              .fontColor($r('app.color.icon_color'))
//              .backgroundColor($r('app.color.background_color'))
//              .width(90)
//          }else{
            Button('查看所有权限', { type: ButtonType.Capsule, stateEffect: true })
              .fontColor($r('app.color.button_color'))
              .backgroundColor($r('app.color.background_color'))
              .width(90).height(48)
              .onTouch((event: TouchEvent) => {
                if (event.type === TouchType.Down) {
                }
                if (event.type === TouchType.Up) {
                }
                if (event.type === TouchType.Move) {
                  if(event.touches[0].x < 0 || event.touches[0].x > 90 || event.touches[0].y > 0 || event.touches[0].y > 48) {
                    this.fontColor = $r('app.color.icon_color') + ''
                  }
                }
              })
//          }
        }.margin({top:16})
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
