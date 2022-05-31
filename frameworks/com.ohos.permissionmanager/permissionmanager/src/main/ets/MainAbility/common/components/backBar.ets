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

import router from '@system.router';
import Constants from '../utils/constant.ets';

@Component
export struct backBar {
  @Prop title: string; // return title name

  build() {
    Column() {
      Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
        Image($r('app.media.left'))
          .objectFit(ImageFit.Contain)
          .height(Constants.BACKBAR_IMAGE_HEIGHT)
          .width(Constants.BACKBAR_IMAGE_WIDTH)
          .margin({
            top: Constants.BACKBAR_IMAGE_MARGIN_TOP,
            left: Constants.BACKBAR_IMAGE_MARGIN_LEFT,
            right: Constants.BACKBAR_IMAGE_MARGIN_RIGHT
          })
          .onClick(() => {
            router.back();
          })
        Text(JSON.parse(this.title))
          .fontColor($r('app.color.text_color'))
          .fontSize(Constants.BACKBAR_TEXT_FONT_SIZE)
          .flexGrow(Constants.BACKBAR_TEXT_FLEX_GROW)
          .fontWeight(FontWeight.Bold)
          .margin({ top: Constants.BACKBAR_TEXT_MARGIN_TOP })
      }
    }
    .height(Constants.BACKBAR_HEIGHT)
    .constraintSize({ minHeight: Constants.BACKBAR_MINHEIGHT })
    .alignItems(HorizontalAlign.Start)
    .backgroundColor($r('app.color.background_color'))
  }
}