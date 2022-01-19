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

import { positionDialog, spaceDialog, privacyDialog } from "../common/components/dialog.ets"
import { titleBar } from "../common/components/titleBar.ets"
import { categoryPage } from "../common/components/category.ets"
import { backBar } from "../common/components/backBar.ets"
import { privacyListItem } from "../common/../common/model/privacyList.ets"
import { dialogData } from "../common/model/dialogDataList.ets"
import router from '@system.router'

@Entry
@Component
struct privacyPage {
  build() {
    Flex({ justifyContent: FlexAlign.Center }) {
      Column() {
        Row() {
          //        titleBar()
          backBar({title: JSON.stringify($r("app.string.privacy"))})
        }
        Row() {
          //        categoryPage()
          Column() {
            Scroll() {
              privacyItem({
                privacyListItem: privacyListItem
              })
            }
          }.width(360)
        }.layoutWeight(1)
      }
    }
  }
}

@Component
struct privacyItem {
  private privacyListItem: any[]
  @State messageList: string[] = [ '', '未开启', '', '']
  @State count: number = 0
//  @State returnList :string[] = []
  positionDialogController: CustomDialogController = new CustomDialogController({
    builder: positionDialog({ cancel: this.positionCancel, confirm: this.positionAccept, messageList: $messageList }),
    cancel: this.positionExist,
    autoCancel: true,
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0 , dy: -12 },
    customStyle: true
  })
  positionCancel() {
    const index = privacyListItem.findIndex((item) => { return item.name === '定位服务' })
    this.messageList[index] = '未开启'
  }
  positionAccept() {
    const index = privacyListItem.findIndex((item) => { return item.name === '定位服务' })
    this.messageList[index] = '已开启'
  }
  positionExist() {
  }
  spaceDialogController: CustomDialogController = new CustomDialogController({
    builder: spaceDialog({ cancel: this.spaceCancel, confirm: this.spaceAccept }),
    cancel: this.spaceExist,
    autoCancel: true,
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0 , dy: -12 },
    customStyle: true
  })
  spaceCancel() {
  }
  spaceAccept() {
  }
  spaceExist() {
  }
  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: privacyDialog({ cancel: this.privacyCancel, confirm: this.privacyAccept, count:this.count }),
    cancel: this.privacyExist,
    autoCancel: true,
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0 , dy: -12 },
    customStyle: true
  })
  privacyAccept() {
      this.count < dialogData.length ? this.count += 1 : this.count = 0
      //      this.returnList.push('0')
      console.info('accept ' + this.count)

  }
  privacyCancel() {
    if (this.count < dialogData.length) {
      this.count += 1
      //      this.returnList.push('1')
    } else {
      this.count = 0
      //      this.returnList = []
    }
    console.info('cancel' + this.count)

  }
  privacyExist() {
    //    this.returnList = []
    console.info("exist")
  }
  build() {
    Row() {
      Column() {
        List() {
          ForEach(this.privacyListItem, (item) => {
            ListItem() {
              Column() {
                Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                  Row() {
                    Text(item.name)
                      .fontSize(18)
                      .fontColor($r('app.color.text_color'))
                      .flexGrow(1)
                    Text(this.messageList[item.index - 1])
                      .fontSize(18)
                      .fontColor($r('app.color.icon_color'))
                    Image(item.icon)
                      .objectFit(ImageFit.Contain)
                      .height(20)
                      .width(20)
                  }.backgroundColor($r('app.color.default_background_color'))
                  .borderRadius('25px')
                  .width('100%')
                  .height('7%')
                  .margin({
                    left: '10vp',
                    bottom: '10vp'
                  })
                }
              }.margin({ right: '20vp'}).onClick(() => {
                if (item.name === '权限管理') {
                  router.push({ uri: 'pages/authority-management' })
                }
                if (item.name === '定位服务') {
                  this.positionDialogController.open()
                }
                if (item.name === '隐私空间') {
                  this.spaceDialogController.open()
                }
                if (item.name === '广告与隐私') {
                  this.privacyDialogController.open()
                }
              })
            }
          }, item => item.toString())
        }
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