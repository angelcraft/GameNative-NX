# GameNative NX - Nintendo Switch homebrew bootstrap + libsolder probe
# Requires devkitPro/devkitA64. libsolder is tracked as a git submodule.

.SUFFIXES:
ifeq ($(strip $(DEVKITPRO)),)
$(error "Set DEVKITPRO in your environment (for example /opt/devkitpro)")
endif

TOPDIR ?= $(CURDIR)
SOLDER_DIR := $(TOPDIR)/third_party/libsolder
SOLDER_LIB := $(SOLDER_DIR)/lib/libsolder.a
include $(DEVKITPRO)/libnx/switch_rules

TARGET := gamenative_nx
APP_TITLE := GameNative NX
APP_AUTHOR := Community project
APP_VERSION := 0.2.0
APP_ICON := $(TOPDIR)/icon.png
export APP_TITLE APP_AUTHOR APP_VERSION APP_ICON

BUILD := build
SOURCES := source
INCLUDES := source $(SOLDER_DIR)/include

ARCH := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE
CFLAGS := -Wall -Wextra -O2 -ffunction-sections $(ARCH) $(INCLUDE) -D__SWITCH__
CXXFLAGS := $(CFLAGS) -fno-rtti -fno-exceptions -std=gnu++17
LDFLAGS := -specs=$(DEVKITPRO)/libnx/switch.specs $(ARCH) -Wl,--gc-sections
LIBS := -lsolder -lnx -lm
LIBDIRS := $(SOLDER_DIR) $(PORTLIBS) $(LIBNX)

ifneq ($(BUILD),$(notdir $(CURDIR)))
export OUTPUT := $(CURDIR)/$(TARGET)
export TOPDIR := $(CURDIR)
export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)

CFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))

export LD := $(CXX)
export OFILES := $(SFILES:.s=.o) $(CPPFILES:.cpp=.o) $(CFILES:.c=.o)
export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
                  $(foreach dir,$(SOLDER_DIR) $(PORTLIBS) $(LIBNX),-I$(dir)/include)
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

.PHONY: all clean libsolder
all: $(BUILD) $(SOLDER_LIB)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

libsolder: $(SOLDER_LIB)

$(SOLDER_LIB):
	@echo "[GameNative NX] Building libsolder"
	@$(MAKE) --no-print-directory -C $(SOLDER_DIR)

$(BUILD):
	@mkdir -p $@

clean:
	@rm -fr $(BUILD) $(TARGET).nro $(TARGET).nacp $(TARGET).elf
	@if [ -d "$(SOLDER_DIR)" ] && [ -f "$(SOLDER_DIR)/Makefile" ]; then $(MAKE) --no-print-directory -C $(SOLDER_DIR) clean; fi

else
DEPENDS := $(OFILES:.o=.d)
NROFLAGS := --icon=$(APP_ICON) --nacp=$(OUTPUT).nacp

all: $(OUTPUT).nro
$(OUTPUT).nro: $(OUTPUT).elf $(OUTPUT).nacp
$(OUTPUT).elf: $(OFILES)
-include $(DEPENDS)
endif
