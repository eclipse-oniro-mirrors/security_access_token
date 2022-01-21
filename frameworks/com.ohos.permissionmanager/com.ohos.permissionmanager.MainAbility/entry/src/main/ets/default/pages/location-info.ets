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

import { applicationListItem } from "../common/model/authorityManagementList.ets"
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
struct locationInfoPage {
  private routerData = router.getParams().routerData
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
              backBar({title: JSON.stringify(this.routerData.name)})
            }
            Row() {
              Column() {
                applicationItem({
                  applicationListItem: applicationListItem
                })
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
              Toggle({ type: ToggleType.Switch, isOn: true })
                .selectedColor($r('app.color.toggle_color'))
                .width(36)
                .height(20)
                .onChange((isOn: boolean) => {
                })
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
        })
      }
    }.padding({ left: 12, right: 12 })
  }
  build() {
    Column() {
      Row() {
        textInput({ placeholder: '搜索应用' })
      }.padding({ left: 12, right: 4 })
      .backgroundColor($r('app.color.background_color'))
      Row() {
        Flex({ alignItems:ItemAlign.Start, justifyContent: FlexAlign.Start }) {
          Column() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text($r('app.string.location_info_message'))
                .fontSize(14)
                .fontColor($r('app.color.secondary_font_color'))
                .margin({ top: 24, left: 12 })
            }
            Scroll() {
              Row() {
                Column() {
                  Row() {
                    List() {
                      ForEach(this.applicationList.slice(0, this.applicationList.length - 1), (item) => {
                        this.ListItemLayout(item, 0)
                      }, item => item.toString())
                      ForEach(this.applicationList.slice(-1), (item, index) => {
                        this.ListItemLayout(item, 1)
                      }, item => item.toString())
                    }
                    .backgroundColor($r('app.color.default_background_color'))
                    .borderRadius(24)
                    .padding({ top: 4, bottom: 4 })
                  }.margin({ top: 24 })
                }.width('100%')
                .height('95%')
                .backgroundColor($r('app.color.background_color'))
              }
            }
          }.padding({ left: 12 })
          Column() {
            alphabetIndexerComponent({ page: 'location-info', applicationList: $applicationList })
          }.width(24).padding({ top: 16 })
        }
      }
      .backgroundColor($r('app.color.background_color'))
    }
  }
}
