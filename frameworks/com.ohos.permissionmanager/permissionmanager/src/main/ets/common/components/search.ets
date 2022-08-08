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

import Constants from '../utils/constant';

@Component
export struct textInput {
  @Prop placeholder: string; // Prompt text when no input
  @Link applicationItem: any; // application info array
  @Link oldApplicationItem: any; // Original application information array
  @Link searchResult: boolean; // search results

  build() {
    Column() {
      Flex({ alignContent: FlexAlign.Start }) {
        TextInput({ placeholder: this.placeholder })
          .backgroundColor($r('app.color.default_background_color'))
          .padding({ left: Constants.TEXTINPUT_PADDING_LEFT })
          .type(InputType.Normal)
          .border({ width: Constants.TEXTINPUT_BORDER_WIDTH, color: $r("app.color.label_color_20"), radius: Constants.TEXTINPUT_BORDER_RADIUS })
          .placeholderColor(Color.Grey)
          .placeholderFont({ size: Constants.TEXTINPUT_PLACEHOLDER_Font_SIZE, weight: FontWeight.Normal, family: "sans-serif", style: FontStyle.Normal })
          .caretColor($r('app.color.secondary_font_color'))
          .height(Constants.TEXTINPUT_HEIGHT)
          .onChange((value: string) => {
            if (value === '' || value === null) {
              this.applicationItem = this.oldApplicationItem;
            } else {
              this.applicationItem = this.oldApplicationItem.filter((item) => {
                  return item.labelId.indexOf(value) > -1;
              })
            }
            if (this.applicationItem.length) {
              this.searchResult = true;
            } else {
              this.searchResult = false;
            }
          })
          .onSubmit((enterKey) => {
          })
          .onEditChanged((isEditing) => {
          })
        Image($r('app.media.search'))
          .objectFit(ImageFit.Contain)
          .width(Constants.TEXTINPUT_IMAGE_WIDTH)
          .height(Constants.TEXTINPUT_IMAGE_HEIGHT)
          .position({ x: Constants.TEXTINPUT_IMAGE_MARGIN_LEFT, y: Constants.TEXTINPUT_IMAGE_MARGIN_TOP })
      }
    }
  }
}