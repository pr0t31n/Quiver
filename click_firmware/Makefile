# Quiver Click firmware — STM32F429ZI (Nucleo-F429ZI)
# Bare-metal + STM32Cube HAL. Requires the ARM GCC toolchain and STM32CubeF4.
#
#   make CUBEF4=/path/to/STM32CubeF4        # build -> build/quiver_click.{elf,hex,bin}
#   make flash                              # flash via st-flash (stlink-tools)
#   make flash-pyocd                        # flash via pyocd
#
# STM32CubeF4:  https://github.com/STMicroelectronics/STM32CubeF4
# ARM toolchain: apt install gcc-arm-none-eabi   (or from ARM Developer)

TARGET   := quiver_click
BUILD    := build
CUBEF4   ?= ./STM32CubeF4          # TODO: point at your STM32CubeF4 checkout

CROSS    := arm-none-eabi-
CC       := $(CROSS)gcc
OBJCOPY  := $(CROSS)objcopy
SIZE     := $(CROSS)size

MCU      := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
DEFS     := -DSTM32F429xx -DUSE_HAL_DRIVER

# --- paths into STM32CubeF4 -------------------------------------------------
HAL      := $(CUBEF4)/Drivers/STM32F4xx_HAL_Driver
CMSIS    := $(CUBEF4)/Drivers/CMSIS
DEVINC   := $(CMSIS)/Device/ST/STM32F4xx/Include
# TODO: confirm these startup + linker files exist for your Cube version.
STARTUP  := $(CUBEF4)/Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f429xx.s
LDSCRIPT := STM32F429ZITx_FLASH.ld   # provide (CubeMX-generated) or copy from a Cube example

INCLUDES := -Isrc -I$(HAL)/Inc -I$(CMSIS)/Include -I$(DEVINC)

CFLAGS   := $(MCU) $(DEFS) $(INCLUDES) -Og -g3 -Wall -ffunction-sections -fdata-sections
LDFLAGS  := $(MCU) -T$(LDSCRIPT) -Wl,--gc-sections -specs=nano.specs -lc -lnosys

# --- sources ----------------------------------------------------------------
APP_SRC  := $(wildcard src/*.c) $(wildcard src/clicks/*.c)
SYS_SRC  := $(CMSIS)/Device/ST/STM32F4xx/Source/Templates/system_stm32f4xx.c
# Minimal HAL modules this firmware uses (add more if you extend it):
HAL_MODS := hal hal_cortex hal_rcc hal_rcc_ex hal_gpio hal_uart hal_spi hal_i2c
HAL_SRC  := $(foreach m,$(HAL_MODS),$(HAL)/Src/stm32f4xx_$(m).c)

C_SRC    := $(APP_SRC) $(SYS_SRC) $(HAL_SRC)
OBJ      := $(addprefix $(BUILD)/,$(notdir $(C_SRC:.c=.o))) $(BUILD)/startup.o
vpath %.c $(sort $(dir $(C_SRC)))

.PHONY: all clean flash flash-pyocd
all: $(BUILD)/$(TARGET).hex $(BUILD)/$(TARGET).bin

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/startup.o: $(STARTUP) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/$(TARGET).elf: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@
	$(SIZE) $@

$(BUILD)/$(TARGET).hex: $(BUILD)/$(TARGET).elf
	$(OBJCOPY) -O ihex $< $@
$(BUILD)/$(TARGET).bin: $(BUILD)/$(TARGET).elf
	$(OBJCOPY) -O binary $< $@

flash: $(BUILD)/$(TARGET).bin
	st-flash write $< 0x08000000

flash-pyocd: $(BUILD)/$(TARGET).hex
	pyocd flash -t stm32f429zi $<

clean:
	rm -rf $(BUILD)
