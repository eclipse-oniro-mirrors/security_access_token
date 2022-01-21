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
import { mediaDocListItem, mediaListItem } from "../common/model/mediaDocList.ets"
import router from '@system.router'
import AccessCtrl from "@ohos.abilityAccessCtrl"

@Entry
@Component
struct mediaDocumentPage {
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
                Scroll() {
                  otherMediaDocItem({
                    mediaDocListItem:mediaDocListItem,
                    mediaListItem:mediaListItem
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
struct otherMediaDocItem {
  aboutToAppear() {
    console.info("yanxi" + "start run testcase!!!!")
    AccessCtrl.createAtManager().verifyAccessToken(0, 'ohos.permission.PLACE_CALL')
      .then((Want) => {
        console.info( "yanxi" + Want);
        console.info( "yanxi" + Want);
      })
      .catch((error) => {
        console.error("yanxi" + 'Operation failed. Cause: ' + error);
      })
  }
  private routerData = router.getParams().routerData
  @State checkList: any[] = [1, 0]
  private mediaDocListItem: any[]
  private mediaListItem: any[]
  build() {
    Column() {
      Row() {
        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
//          Text(this.mediaListItem[0].name)
//          this.mediaListItem.filter(item => {
//
//          })
          Image(this.mediaListItem[0].image)
            .width(64)
            .height(64)
            .margin({left:24,right:12})
          Column() {
            Row() {
              Text(this.routerData.name)
                .fontSize(16)
                .fontColor("#182431")
            }
            Row() {
              Text(this.routerData.version)
                .fontSize(12)
            }
          }
        }
      }
      Row() {
        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
          Row() {
            Text(this.routerData.use)
              .fontSize(12)
          }.margin({left:36,right:12})
        }
      }
      .margin({top:24})
      Row() {
        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
          Row() {
            Text(this.routerData.name + '访问权限')
              .fontSize(16)
          }.margin({left:36,right:12})
        }
      }
      .height(48)
      .margin({top:12})
      Column() {
        List() {
          ForEach(this.mediaDocListItem, (item) => {
            ListItem() {
              Column() {
                Row() {
                  Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                    Row() {
                      Text(item.name)
                        .fontSize(16)
                        .fontColor($r('app.color.text_color'))
                        .flexGrow(1)
                      Radio({ group:item.groupName,value:item.index })
                        .width(24)
                        .height(24)
                        .checked(this.checkList[item.index - 1])
                        .onChange((isChecked) => {
                          if (item.index - 1) {
                            if (!isChecked) {
                              this.checkList[1] = 0
                            }
                            this.checkList = [0, 1]
                          } else {
                            if (!isChecked) {
                              this.checkList[1] = 1
                            }
                            this.checkList = [1, 0]
                          }
                        })
                    }.backgroundColor($r('app.color.default_background_color'))
                    .width('100%')
                    .height('48')
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
        .borderRadius(24)
        .backgroundColor($r('app.color.default_background_color'))
        .padding({ left: 12, right: 12, top: 3, bottom: 4 })
      }
      .padding({ left: 24, right: 24 })
      .width('100%')
      .height('100%')
      .backgroundColor($r('app.color.background_color'))
    }
    .backgroundColor($r('app.color.background_color'))
  }
}