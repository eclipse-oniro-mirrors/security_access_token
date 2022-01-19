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

import { permissionAccessRecordListItem } from "../common/model/permissionAccessRecordList.ets"
import { titleBar } from "../common/components/titleBar.ets"
import { categoryPage } from "../common/components/category.ets"
import { backBar } from "../common/components/backBar.ets"
import router from '@system.router'

@Extend(Text) function customizeText(fontSize: string) {
  .fontSize(fontSize)
  .fontColor($r('app.color.text_color'))
}
@Extend(Image) function customizeImage(width: number, height: number) {
  .objectFit(ImageFit.Contain)
  .width(width)
  .height(height)
}

@Entry
@Component
struct permissionAccessRecordPage {
  build() {
    Flex({ justifyContent: FlexAlign.Center }) {
      Column() {
        Row() {
          //        titleBar()
          backBar({ title: JSON.stringify($r('app.string.permission_access_record'))})
        }
        Row() {
          //        categoryPage()
          Column() {
            Column() {
              Flex({ justifyContent: FlexAlign.Start }) {
                Text($r('app.string.authority_message'))
                  .fontSize("16vp")
                  .margin({
                    left: '15vp'
                  })
              }
              .backgroundColor($r('app.color.background_color'))
              Scroll() {
                permissionAccessRecordItem({
                  permissionAccessRecordListItem: permissionAccessRecordListItem,
                })
              }
            }
          }.width(360)
        }
        .layoutWeight(1)
      }
    }
  }
}

@Component
struct permissionAccessRecordItem {
  private permissionAccessRecordListItem: any[]
  @State collapseList: boolean[] = new Array(permissionAccessRecordListItem.length).fill(false)
  @State iconList: any[] = new Array(permissionAccessRecordListItem.length).fill($r('app.media.downarrow'))
  build() {
    Row() {
      Column() {
        List() {
          ForEach(this.permissionAccessRecordListItem, (item) => {
            ListItem() {
              Column() {
                Row() {
                  Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                    Image(item.image1)
                      .customizeImage(40, 40)
                      .margin({
                        left: "10vp",
                        right: "5vp"
                      })
                    Column() {
                      Row() {
                        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                          Text(item.name1)
                            .customizeText('16vp')
                        }
                        .flexGrow(1)
                        Image(this.iconList[item.index - 1])
                          .customizeImage(20, 20)
                          .margin({
                            top: '20vp',
                            right: '40vp'
                          })
                      }
                      Row() {
                        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                          Image(item.image2)
                            .customizeImage(20, 20)
                            .margin({
                              top: '-8vp'
                            })
                        }
                      }
                    }
                  }
                  .margin({
                    top: '10vp',
                    bottom: '10vp'
                  })
                }.onClick(() => {
                  if (this.collapseList[item.index - 1]) {
                    this.collapseList[item.index - 1] = false
                    this.iconList[item.index - 1] = $r('app.media.downarrow')
                  } else {
                    this.collapseList[item.index - 1]= true
                    this.iconList[item.index - 1] = $r('app.media.uparrow')
                  }
                })
                if (this.collapseList[item.index - 1]) {
                  Row() {
                    Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                      Image(item.image2)
                        .customizeImage(30, 30)
                        .margin({
                          left: "15vp",
                          right: "5vp"
                        })
                      Column() {
                        Row() {
                          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                            Text(item.name2)
                              .customizeText('16vp')
                              .margin({
                                top: '2vp'
                              })
                          }
                        }
                        Row() {
                          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                            Text("访问次数：" + item.visits + "; " + "最近访问：" + item.lastVisitTime)
                              .customizeText('16vp')
                              .margin({
                                top: '2vp'
                              })
                          }
                        }
                      }
                    }
                  }.margin({
                    bottom: '20vp'
                  })
                }
              }.backgroundColor($r('app.color.default_background_color'))
              .borderRadius('25px')
              .width('100%')
              .margin({
                left: '10vp',
                top: '10vp'
              }).onClick(() => {
                if (item.name === '权限管理') {
                  router.push({ uri: 'pages/authority_management' })
                }
              })
            }
          }, item => item.index.toString())
        }
      }
      .useSizeType({
        xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
        md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
      })
      .width('100%')
      .height('100%')
      .backgroundColor($r('app.color.background_color'))
    }.useSizeType({
      xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
      md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
    })
  }
}
