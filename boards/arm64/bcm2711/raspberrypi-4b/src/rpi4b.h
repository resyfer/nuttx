/****************************************************************************
 * boards/arm64/bcm2711/raspberrypi-4b/src/rpi4b.h
 *
 * Author: Matteo Golin
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#ifndef __BOARDS_ARM64_BCM2711_RASPBERRYPI_4B_SRC_RPI4B_H
#define __BOARDS_ARM64_BCM2711_RASPBERRYPI_4B_SRC_RPI4B_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

/****************************************************************************
 * Public Functions Definitions
 ****************************************************************************/

/****************************************************************************
 * Name: rpi4b_bringup
 *
 * Description:
 *   Bring up board features
 *
 ****************************************************************************/

#if defined(CONFIG_BOARDCTL) || defined(CONFIG_BOARD_LATE_INITIALIZE)
int rpi4b_bringup(void);
#endif

/****************************************************************************
 * Name: rpi4b_sdmmc_initialize
 *
 * Description:
 *   Initialize uSD card on EMMC2 as an MMCSD device.
 *
 ****************************************************************************/

#if defined(CONFIG_RPI4B_SDMMC)
int rpi4b_sdmmc_initialize(void);
#endif

#if defined(CONFIG_DEV_GPIO)
int bcm2711_dev_gpio_init(void);
#endif /* defined(CONFIG_DEV_GPIO) */

/* == UART == */

/* UART 0: GPIO 14 (ALT0=0) and GPIO 15 (ALT0=0) */
#if (CONFIG_RPI4B_GPIO14 == 0) && (CONFIG_RPI4B_GPIO15 == 0)
#  define RPI4B_UART0
#endif

/* UART 1: GPIO 14 (ALT5=5) and GPIO 15 (ALT5=5) */
#if (CONFIG_RPI4B_GPIO14 == 5) && (CONFIG_RPI4B_GPIO15 == 5)
#  define RPI4B_UART1
#endif

/* UART 2: GPIO 0 (ALT4=4) and GPIO 1 (ALT4=4) */
#if (CONFIG_RPI4B_GPIO0 == 4) && (CONFIG_RPI4B_GPIO1 == 4)
#  define RPI4B_UART2
#endif

/* UART 3: GPIO 4 (ALT4=4) and GPIO 5 (ALT4=4) */
#if (CONFIG_RPI4B_GPIO4 == 4) && (CONFIG_RPI4B_GPIO5 == 4)
#  define RPI4B_UART3
#endif

/* UART 4: GPIO 8 (ALT4=4) and GPIO 9 (ALT4=4) */
#if (CONFIG_RPI4B_GPIO8 == 4) && (CONFIG_RPI4B_GPIO9 == 4)
#  define RPI4B_UART4
#endif

/* UART 5: GPIO 12 (ALT4=4) and GPIO 13 (ALT4=4) */
#if (CONFIG_RPI4B_GPIO12 == 4) && (CONFIG_RPI4B_GPIO13 == 4)
#  define RPI4B_UART5
#endif

/* == I2C == */

/* I2C 0: GPIO 0 (ALT0=0) and GPIO 1 (ALT0=0) */
#if (CONFIG_RPI4B_GPIO0 == 0) && (CONFIG_RPI4B_GPIO1 == 0)
#  define RPI4B_I2C0
#endif

/* I2C 1: GPIO 2 (ALT0=0) and GPIO 3 (ALT0=0) */
#if (CONFIG_RPI4B_GPIO2 == 0) && (CONFIG_RPI4B_GPIO3 == 0)
#  define RPI4B_I2C1
#endif

/* == SPI == */

/* SPI 0: GPIO 7, 8, 9, 10, 11 (All ALT0=0) */
#if (CONFIG_RPI4B_GPIO7 == 0) && (CONFIG_RPI4B_GPIO8 == 0) && \
    (CONFIG_RPI4B_GPIO9 == 0) && (CONFIG_RPI4B_GPIO10 == 0) && \
    (CONFIG_RPI4B_GPIO11 == 0)
#  define RPI4B_SPI0
#endif

#endif /* __BOARDS_ARM64_BCM2711_RASPBERRYPI_4B_SRC_RPI4B_H */
