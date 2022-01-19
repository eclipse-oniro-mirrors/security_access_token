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

import { authorityListItem, messageListItem, appInstallListItem, otherPermissionsListItem, applicationListItem } from "../common/model/authorityManagementList.ets"
import { titleBar } from "../common/components/titleBar.ets"
import { categoryPage } from "../common/components/category.ets"
import { backBar } from "../common/components/backBar.ets"
import { alphabetIndexerComponent } from "../common/components/alphabeticalIndex.ets"
import { textInput } from "../common/components/search.ets"
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
    Flex({ justifyContent: FlexAlign.Center }) {
      Column() {
        Row() {
          //        titleBar()
          backBar( { title: JSON.stringify($r('app.string.authority_management')) })
        }
        Row() {
          //        categoryPage()
          Column() {
            Column() {
              Stack() {
                Tabs() {
                  TabContent() {
                    Scroll() {
                      authorityItem({
                        authorityListItem: authorityListItem,
                        messageListItem: messageListItem,
                        appInstallListItem: appInstallListItem,
                        otherPermissionsListItem: otherPermissionsListItem
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
          }.width('100%')
        }
        .useSizeType({
          xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
          md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
        })
        .layoutWeight(1)
        .width(360)
      }
    }
  }
}

@Component
struct authorityItem {
  private authorityListItem: any[]
  private messageListItem: any[]
  private appInstallListItem: any[]
  private otherPermissionsListItem: any[]
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
        if (item.name === '其他权限') {
          router.push({
            uri: 'pages/other-permissions',
          })
        }else if (item.name === '位置信息') {
          router.push({
            uri: 'pages/location-info',
          })
        }else if (item.name === '媒体和文件') {
          router.push({
            uri: 'pages/media-documents',
            params: { routerData: item }
          })
        }else{
          router.push({
            uri: 'pages/media-documents',
            params: { routerData: item }
          })
        }

      })
    }
  }.padding({ left: 12, right: 12 })
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
        Row() {
          List() {
            ForEach(this.appInstallListItem, (item) => {
              this.ListItemLayout(item, this.appInstallListItem)
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.margin({ top: 12 }).padding({ left: 12, right: 12 })
        Row() {
          List() {
            ForEach(this.otherPermissionsListItem, (item) => {
              this.ListItemLayout(item, this.otherPermissionsListItem)
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(24).padding({ top: 4, bottom: 4 })
        }.margin({ top: 12 }).padding({ left: 12, right: 12 })
      }.width('100%')
      .backgroundColor($r('app.color.background_color'))
    }.useSizeType({
      xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
      md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
    })
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
      }.padding({ left: 12, top: 8 })
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
            .padding({ right: 0 })
          }
        }.useSizeType({
          xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
          md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
        })
      }
    }
  }
}
