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

import { authorityListItem, messageListItem, applicationListItem } from "../common/model/authorityManagementList.ets"
import { backBar } from "../common/components/backBar.ets"
import { alphabetIndexerComponent } from "../common/components/alphabeticalIndex.ets"
import { textInput } from "../common/components/search.ets"
import router from '@system.router'
import bundle from "@ohos.bundle"

@Extend(Text) function customizeText(fontSize: string) {
  .fontSize(fontSize)
  .fontColor($r('app.color.text_color'))
}
@Extend(Image) function customizeImage(width: number, height: number) {
  .objectFit(ImageFit.Contain)
  .width(width)
  .height(height)
}
@Extend(Row) function customizeRow() {
  .backgroundColor($r('app.color.default_background_color'))
  .width('500%')
  .height('7%')
  .borderRadius('20px')
  .margin({
    left: '10vp'
  })
}

@Entry
@Component
struct authorityManagementPage {

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
              backBar( { title: JSON.stringify($r('app.string.authority_management')) })
            }
            Row() {
              Column() {
                Column() {
                  Stack() {
                    Tabs() {
                      TabContent() {
                        Scroll() {
                          authorityItem({
                            authorityListItem: authorityListItem,
                            messageListItem: messageListItem
                          })
                        }
                      }.tabBar('权限')

                      TabContent() {
                        Scroll() {
                          applicationItem({
                            applicationListItem: applicationListItem,
                          })
                        }
                      }.tabBar('应用')
                    }
                    .backgroundColor($r('app.color.background_color'))
                    .barWidth(744)
                    .barMode(BarMode.Scrollable)
                  }.height('100%')
                }
              }
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
struct authorityItem {
  private authorityListItem: any[]
  private messageListItem: any[]
  @Builder ListItemLayout(item, list) {
  ListItem() {
    Row() {
      Column() {
        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
          Row() {
            Image(item.image)
              .customizeImage(24, 24)
              .margin({ right: 16 })
            Text(item.name)
              .fontSize(16)
              .fontColor($r('app.color.text_color'))
              .flexGrow(1)
            Image(item.icon)
              .customizeImage(12, 24)
          }
          .width('100%')
          .height(56)
        }
        if (item.index !== list.length) {
          Row() {
            Column()
              .backgroundColor($r('app.color.text_decoration_color'))
              .width('100%')
              .height('2vp')
          }
        }
      }.onClick(() => {
        if (item.name === '日历') {
          router.push({
            uri: 'pages/calendar',
            params: { routerData: item }
          })
        } else {
          router.push({
            uri: 'pages/location-info',
            params: { routerData: item }
          })
        }

      })
    }
  }.padding({ left: 12, right: 12 })
}
  aboutToAppear() {
    console.info("start run testcase!!!!")
//    bundle.getAllApplicationInfo(0x00000000,1)
//      .then((Want) => {
//        console.info( "yanxi" + JSON.stringify(Want));
//        console.log( "yanxi" + JSON.stringify(Want));
//      })
//      .catch((error) => {
//        console.error('Operation failed. Cause: ' + JSON.stringify(error));
//      })

  }
  build() {
    Row() {
      Column() {
        Row() {
          List() {
            ForEach(this.authorityListItem, (item) => {
              this.ListItemLayout(item, this.authorityListItem)
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.padding({ left: 12, right: 12, top: 8 })
        Row() {
          List() {
            ForEach(this.messageListItem, (item) => {
              this.ListItemLayout(item, this.messageListItem)
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.margin({ top: 12 }).padding({ left: 12, right: 12 })
      }.width('100%')
      .backgroundColor($r('app.color.background_color'))
    }
  }
}

@Component
struct applicationItem {
  @State applicationList: any[] = applicationListItem
  private applicationListItem: any[]

  @Builder ListItemLayout(item, index) {
    ListItem() {
      Row() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              Image(item.image)
                .customizeImage(40, 40)
                .margin({ right: 16 })
              Text(item.name)
                .fontSize(16)
                .fontColor($r('app.color.text_color'))
                .flexGrow(1)
              Text(item.message)
                .fontSize(14)
                .fontColor($r('app.color.icon_color'))
                .margin({ right: 4 })
              Image(item.icon)
                .customizeImage(12, 24)
            }
            .width('100%')
            .height(72)
            .constraintSize({ minHeight: "72vp" })
          }
          if (index === 0) {
            Row() {
              Column()
                .backgroundColor($r('app.color.text_decoration_color'))
                .width('100%')
                .height('2vp')
            }
          }
        }.onClick(() => {
          router.push({
            uri: 'pages/app-name-plus',
            params: { routerData: item }
          })
        })
      }
    }.padding({ left: 12, right: 12 })
  }
  build() {
    Column() {
      Row() {
        textInput({ placeholder: '搜索应用' })
//        .width("100%")
      }.padding({ left: 12, top: 8, right: 4 })
      Scroll() {
        Row() {
          Flex({ alignItems: ItemAlign.Start }) {
            Column() {
              Row() {
                List() {
                  ForEach(this.applicationList.slice(0, this.applicationList.length - 1), (item) => {
                    this.ListItemLayout(item, 0)
                  }, item => item.toString())
                  ForEach(this.applicationList.slice(-1), (item, index) => {
                    this.ListItemLayout(item, 1)
                  }, item => item.toString())
                }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
              }.margin({ top: 12 }).padding({ left: 12 })
            }
            .backgroundColor($r('app.color.background_color'))
            .height("89%")
            Column() {
              alphabetIndexerComponent({ page: 'authority-management', applicationList: $applicationList })
            }
            .margin({ top: 12 })
            .width(24)
          }
        }
      }
    }
  }
}
