/****************************************************************************
 * boards/arm64/bcm2711/raspberrypi-4b/src/rpi4b_gpio.c
 *
 * Author: Matteo Golin <matteo.golin@gmail.com>
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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <arch/irq.h>
#include <assert.h>
#include <debug.h>
#include <nuttx/irq.h>
#include <sys/types.h>
#include <syslog.h>

#include <nuttx/ioexpander/gpio.h>

#include <arch/board/board.h>

#include "bcm2711_gpio.h"
#include "chip.h"

#if defined(CONFIG_DEV_GPIO) && !defined(CONFIG_GPIO_LOWER_HALF)

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/**
 * While BCM2711 has 58 GPIO pins, the RPi 4b's 40 pin header only has the
 * GPIO pins in bank 1 (ie. GPIO pin 0 to 27).
 */

#define RPI4B_NGPIO 28 // 0-27

/* Interrupt pins */

/* TODO: why can't you select interrupt event type??? */

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* GPIO device on the BCM2711 */

struct bcm2711_gpio_dev_s
{
  struct gpio_dev_s gpio; /* Underlying GPIO device */
  uint8_t           pin;  /* The index of the pin in its list. */
};

enum bcm2711_gpio_pull_e
{
  BCM2711_GPIO_PULL_NO,
  BCM2711_GPIO_PULL_HIGH,
  BCM2711_GPIO_PULL_LOW
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int  rpi4b_gpout_read(struct gpio_dev_s *dev, bool *value);
static int  rpi4b_gpout_write(struct gpio_dev_s *dev, bool value);
static int  rpi4b_gpin_read(struct gpio_dev_s *dev, bool *value);
static void rpi4b_set_gpio_funcs(void);
static int  rpi4b_register_gpio_output(uint8_t pin);
static int  rpi4b_register_gpio_input(uint8_t pin);
static void rpi4b_register_pins(void);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* GPIO operations for output pins. */

static const struct gpio_operations_s gpout_ops =
{
  .go_read   = rpi4b_gpout_read,
  .go_write  = rpi4b_gpout_write,
  .go_attach = NULL,
  .go_enable = NULL,
};

/* GPIO operations for input pins. */

static const struct gpio_operations_s gpin_ops =
{
  .go_read   = rpi4b_gpin_read,
  .go_write  = NULL,
  .go_attach = NULL,
  .go_enable = NULL,
};

/* TODO: Other types of ops */

/* GPIO pin functions */

static enum bcm2711_gpio_func_e rpi4b_gpios[RPI4B_NGPIO];
static struct bcm2711_gpio_dev_s rpi4b_gpio_ops[RPI4B_NGPIO];

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void rpi4b_set_gpio_funcs(void)
{
  rpi4b_gpios[0]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO0;
  rpi4b_gpios[1]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO1;
  rpi4b_gpios[2]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO2;
  rpi4b_gpios[3]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO3;
  rpi4b_gpios[4]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO4;
  rpi4b_gpios[5]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO5;
  rpi4b_gpios[6]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO6;
  rpi4b_gpios[7]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO7;
  rpi4b_gpios[8]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO8;
  rpi4b_gpios[9]  = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO9;
  rpi4b_gpios[10] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO10;
  rpi4b_gpios[11] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO11;
  rpi4b_gpios[12] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO12;
  rpi4b_gpios[13] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO13;
  rpi4b_gpios[14] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO14;
  rpi4b_gpios[15] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO15;
  rpi4b_gpios[16] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO16;
  rpi4b_gpios[17] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO17;
  rpi4b_gpios[18] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO18;
  rpi4b_gpios[19] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO19;
  rpi4b_gpios[20] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO20;
  rpi4b_gpios[21] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO21;
  rpi4b_gpios[22] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO22;
  rpi4b_gpios[23] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO23;
  rpi4b_gpios[24] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO24;
  rpi4b_gpios[25] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO25;
  rpi4b_gpios[26] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO26;
  rpi4b_gpios[27] = (enum bcm2711_gpio_func_e) CONFIG_RPI4B_GPIO27;
}

/****************************************************************************
 * Name: gpout_read
 *
 * Description:
 *     Read the output pin's current status (0 or 1).
 *
 * Input parameters:
 *     dev - The GPIO device structure.
 *     value - A pointer to the location to store the pin status.
 ****************************************************************************/

static int rpi4b_gpout_read(struct gpio_dev_s *dev, bool *value)
{
  struct bcm2711_gpio_dev_s *bcm2711gpio =
        (struct bcm2711_gpio_dev_s *)(dev);

  DEBUGASSERT(bcm2711gpio != NULL);
  DEBUGASSERT(value != NULL);
  DEBUGASSERT(bcm2711gpio->pin < RPI4B_NGPIO);

  *value = bcm2711_gpio_pin_get(bcm2711gpio->pin);

  return 0;
}

/****************************************************************************
 * Name: gpout_write
 *
 * Description:
 *     Write a value to a GPIO output pin.
 *
 * Input parameters:
 *     dev - The GPIO device struct of the pin to write to.
 *     value - The value to write to the pin.
 ****************************************************************************/

static int rpi4b_gpout_write(struct gpio_dev_s *dev, bool value)
{
  struct bcm2711_gpio_dev_s *bcm2711_gpio =
        (struct bcm2711_gpio_dev_s *)(dev);

  DEBUGASSERT(bcm2711_gpio != NULL);
  DEBUGASSERT(bcm2711_gpio->pin < RPI4B_NGPIO);

  gpioinfo("Writing %" PRIu8 " to pin %" PRIu32 "\n", value,
           bcm2711_gpio->pin);
  bcm2711_gpio_pin_set(bcm2711_gpio->pin, value);

  return 0;
}

/****************************************************************************
 * Name: gpin_read
 *
 * Description:
 *     Read the input pin's current status (0 or 1).
 *
 * Input parameters:
 *     dev - The GPIO device structure.
 *     value - A pointer to the location to store the pin status.
 ****************************************************************************/

static int rpi4b_gpin_read(struct gpio_dev_s *dev, bool *value)
{
  struct bcm2711_gpio_dev_s *bcm2711_gpio =
        (struct bcm2711_gpio_dev_s *)(dev);

  DEBUGASSERT(bcm2711_gpio != NULL);
  DEBUGASSERT(value != NULL);
  DEBUGASSERT(bcm2711_gpio->pin < RPI4B_NGPIO);

  *value = bcm2711_gpio_pin_get(bcm2711_gpio->pin);

  return 0;
}

static enum bcm2711_gpio_pull_e rpi4b_gpio_pull_status(int pin)
{
  DEBUGASSERT(pin < RPI4B_NGPIO);

  /* BCM2711 Peripheral Doc */

  if (pin <= 8)
    {
      return BCM2711_GPIO_PULL_HIGH;
    }
  else
    {
      return BCM2711_GPIO_PULL_LOW;
    }

  /* 0-8 are HIGH, 9-27 are LOW. Other pins are not supported in RPI 4B */
}

static int rpi4b_register_gpio_output(uint8_t pin)
{
  int                      ret          = OK;
  enum bcm2711_gpio_pull_e pull_status;

  gpioinfo("Registering GPIO pin %" PRIu8 " as OUTPUT", pin);

  rpi4b_gpio_ops[pin].gpio.gp_pintype = GPIO_OUTPUT_PIN;
  rpi4b_gpio_ops[pin].gpio.gp_ops     = &gpout_ops;
  rpi4b_gpio_ops[pin].pin             = pin;

  ret = gpio_pin_register(&rpi4b_gpio_ops[pin].gpio, pin);
  if (predict_false(ret != OK))
    {
      goto errout;
    }

  pull_status = rpi4b_gpio_pull_status(pin);
  switch (pull_status)
    {
      case BCM2711_GPIO_PULL_NO:
        bcm2711_gpio_set_pulls(pin, false, false);
        break;

      case BCM2711_GPIO_PULL_HIGH:
        bcm2711_gpio_set_pulls(pin, true, false);
        break;

      case BCM2711_GPIO_PULL_LOW:
        bcm2711_gpio_set_pulls(pin, false, true);
        break;
    }

  bcm2711_gpio_set_func(pin, BCM_GPIO_OUTPUT);
  bcm2711_gpio_pin_set(pin, false);
  return ret;

errout:
  return ret;
}

static int rpi4b_register_gpio_input(uint8_t pin)
{
  int                      ret          = OK;
  enum bcm2711_gpio_pull_e pull_status;

  gpioinfo("Registering GPIO pin %" PRIu8 " as INPUT", pin);

  rpi4b_gpio_ops[pin].gpio.gp_pintype = GPIO_INPUT_PIN;
  rpi4b_gpio_ops[pin].gpio.gp_ops     = &gpin_ops;
  rpi4b_gpio_ops[pin].pin             = pin;

  ret = gpio_pin_register(&rpi4b_gpio_ops[pin].gpio, pin);
  if (predict_false(ret != OK))
    {
      goto errout;
    }

  pull_status = rpi4b_gpio_pull_status(pin);
  switch (pull_status)
    {
      case BCM2711_GPIO_PULL_NO:
        bcm2711_gpio_set_pulls(pin, false, false);
        break;

      case BCM2711_GPIO_PULL_HIGH:
        bcm2711_gpio_set_pulls(pin, true, false);
        break;

      case BCM2711_GPIO_PULL_LOW:
        bcm2711_gpio_set_pulls(pin, false, true);
        break;
    }

  bcm2711_gpio_set_func(pin, BCM_GPIO_INPUT);
  return ret;

errout:
  return ret;
}

static void rpi4b_register_pins(void)
{
  int     ret = OK;
  uint8_t i   = 0;

  for (i = 0; i < RPI4B_NGPIO; i++)
    {
      switch (rpi4b_gpios[i])
        {
          case BCM_GPIO_OUTPUT:
            ret = rpi4b_register_gpio_output(i);
            if (predict_false(ret != OK))
              {
                gpiowarn("Problem registering GPIO %" PRIu8 " as OUTPUT", i);
              }
            break;
          case BCM_GPIO_INPUT:
            ret = rpi4b_register_gpio_input(i);
            if (predict_false(ret != OK))
              {
                gpiowarn("Problem registering GPIO %" PRIu8 " as INPUT", i);
              }
            break;
          default:
            gpiowarn("Unsupported function '%" PRIu8 "' on GPIO %" PRIu8"\n",
                     rpi4b_gpios[i], i);
        }
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: bcm2711_dev_gpio_init
 ****************************************************************************/

int bcm2711_dev_gpio_init(void)
{
  rpi4b_set_gpio_funcs();
  rpi4b_register_pins();
  return OK;
}

#endif /* defined(CONFIG_DEV_GPIO) && !defined(CONFIG_GPIO_LOWER_HALF) */
