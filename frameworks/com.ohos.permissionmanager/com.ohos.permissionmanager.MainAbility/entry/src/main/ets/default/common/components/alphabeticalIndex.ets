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

import { applicationListItem } from "../model/authorityManagementList.ets"

@Component
export struct alphabetIndexerComponent {
  @State alphabeticalIndex: number = 0
  @Prop page: string
  @Link applicationList: any[]
  private value: string[] = ['#', '☆', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
  filterData(index) {
    this.alphabeticalIndex = index
    if (index === 0 || index === 1) {
      this.applicationList = applicationListItem
    }
    else {
      this.applicationList = applicationListItem.filter((item) => {
        return item.alphabeticalIndex === this.value[index]
      })
    }
  }

  build() {
    Flex({ justifyContent: FlexAlign.Start }) {
      AlphabetIndexer({ ArrayValue: this.value, selected: this.alphabeticalIndex })
        .selectedColor(0xffffff) // 选中颜色
        .popupColor(0xFFFAF0) // 弹出框颜色
        .selectedBackgroundColor(0xCCCCCC) // 选中背景颜色
        .popupBackground(0xD2B48C) // 弹出框背景颜色
        .usingPopup(true) // 是否显示弹出框
        .selectedFont({ size: 12, weight: FontWeight.Bolder }) // 选中的样式
        .popupFont({ size: 30, weight: FontWeight.Bolder }) // 弹出框的演示
        .itemSize(16) // 每一项的大小正方形
        .alignStyle(IndexerAlign.Left) // 左对齐
        .onSelected((index: number) => {
          if (this.page === 'location-info') {
            this.filterData(index)
          }
          if (this.page === 'authority-management') {
            this.filterData(index)
          }
          console.info(this.value[index] + '被选中了') // 选中的事件
        })
        .height(448)
        .width(24)
    }
  }
}