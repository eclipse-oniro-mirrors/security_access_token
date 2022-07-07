/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

import Constants from '../utils/constant.ets';

@Component
export struct alphabetIndexerComponent {
  private value: string[] = [
    '#',
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
    'G',
    'H',
    'I',
    'J',
    'K',
    'L',
    'M',
    'N',
    'O',
    'P',
    'Q',
    'R',
    'S',
    'T',
    'U',
    'V',
    'W',
    'X',
    'Y',
    'Z'
  ]; // Array of alphabetically indexed names
  @Link applicationItem: any; // application info array
  @Link oldApplicationItem: any; // Original application information array
  @State index: number = 0; // alphabetical index

  build() {
    AlphabetIndexer({ arrayValue: this.value, selected: this.index })
      .selectedColor($r('app.color.selected_Color')) // selected color
      .popupColor($r('app.color.popup_Color')) // popover color
      .selectedBackgroundColor($r('app.color.selected_Background_Color')) // Check background color
      .popupBackground($r('app.color.popup_Background_Color')) // popover background color
      .usingPopup(true) // whether to show a popup
      .selectedFont({ size: Constants.ALPHABETINDEXER_SELECTEDFONT_SIZE, weight: FontWeight.Bolder }) // selected style
      .popupFont({ size: Constants.ALPHABETINDEXER_POPUPFONT_SIZE, weight: FontWeight.Bolder }) // Demo of the popup
      .itemSize(Constants.ALPHABETINDEXER_ITEMSIZE) // size square of each item
      .alignStyle(IndexerAlign.Left) // Align left
      .onSelected((index: number) => {
        this.index = index;
        if (this.value[index] === '#' || this.value[index] === '☆') {
          this.applicationItem = this.oldApplicationItem;
        } else {
          this.applicationItem = this.oldApplicationItem.filter((item) => {
            return item.alphabeticalIndex.toUpperCase() === this.value[index];
          })
        }
      })
      .height(Constants.ALPHABETINDEXER_HEIGHT)
      .width(Constants.ALPHABETINDEXER_WIDTH)
  }
}