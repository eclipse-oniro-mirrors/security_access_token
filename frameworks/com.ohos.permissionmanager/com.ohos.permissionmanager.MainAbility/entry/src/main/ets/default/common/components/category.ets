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

import { categoryListItem } from "../model/categoryList.ets"

@Component
export struct categoryPage {
  build() {
    Column() {
      categoryList({
        categoryListItem: categoryListItem,
      })
    }
  }
}

@Component
struct categoryList {
  private categoryListItem: any[]
  @State color: string[] = [
    "#ffffff",
    "#ffffff",
    "#ffffff",
    "#ffffff",
    "#ffffff",
    "#ffffff",
    "#ffffff",
    "#e5f3ff",
    "#ffffff",
    "#ffffff",
    "#ffffff"
  ]
  private listState: number = 0

  build() {
    Column() {
      List() {
        ForEach(this.categoryListItem, (item) => {
          ListItem() {
            Column() {
              Row() {
                Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                  Image(item.image)
                    .objectFit(ImageFit.Contain)
                    .height(25)
                    .width(25)
                    .margin({
                      left: "10vp",
                      right: "15vp"
                    })
                  Text(item.name)
                    .fontSize("18vp")
                    .fontColor($r('app.color.text_color'))
                    .flexGrow(1)
                  Image(item.icon)
                    .objectFit(ImageFit.Contain)
                    .height(20)
                    .width(20)
                }
              }.margin({
                top: '16vp'
              }
              )
              Row() {
                Column()
                  .backgroundColor($r('app.color.text_decoration_color'))
                  .width('100%')
                  .height('2vp')
                  .margin({
                    top: '10vp',
                    left: '24%'
                  })
              }
            }
            .backgroundColor(this.color[item.index - 1])
            .width('100%')
            .height('10%')
            .borderRadius('25px')
            .margin({
              bottom: '10vp'
            })
            .onClick(() => {
              if (this.color[item.index - 1] == "#ffffff") {
                for (var i = 0; i < this.color.length; i++) {
                  if (i == item.index - 1) {
                    this.color[i] = "#e5f3ff"
                  } else {
                    this.color[i] = "#ffffff"
                  }
                }
              }
              this.listState = item.index - 1;
              console.debug("you click" + this.listState)
            })
          }
        }, item => item.index.toString())
    }.width('40%')
    Divider()
      .vertical(true)
      .color($r('app.color.divider_color'))
      .width('2vp')
      .margin({
        top: "8vp",
        bottom: "8vp"
      })
    }.useSizeType({
      xs: { span: 1, offset: 0 }, sm: { span: 1, offset: 0 },
      md: { span: 1, offset: 0 }, lg: { span: 2, offset: 0 }
    })
  }
}
