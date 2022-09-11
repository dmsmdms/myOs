BUILD_DIR := build
TARGET := $(BUILD_DIR)/init

UNAME := $(shell uname -p)
ARCH_x86_46 := $(filter x86_64, $(UNAME))
ARCH_ARMV6 := $(filter armv6, $(UNAME))

CFLAGS := -c -MD -O3 -march=native
ifdef ARCH_x86_46
CFLAGS := $(CFLAGS) -DEMUL
endif
ifdef ARCH_ARMV6
CFLAGS := $(CFLAGS) -mfloat-abi=hard -mfpu=vfp
endif

VPATH := $(shell find system -type d) $(BUILD_DIR)
SOURCES := $(foreach dir, $(VPATH), $(wildcard $(dir)/*.c))
WEB_UI := $(foreach dir, $(VPATH), $(wildcard $(dir)/*.html $(dir)/*.css $(dir)/*.js))
WEB_OBJECTS := $(patsubst %, $(BUILD_DIR)/%.o, $(notdir $(WEB_UI)))
OBJECTS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(notdir $(SOURCES)))

all: $(TARGET)
$(TARGET): $(OBJECTS) $(WEB_OBJECTS)
	@ mkdir -p $(@D)
	gcc $(OBJECTS) $(WEB_OBJECTS) -o $@

$(BUILD_DIR)/%.o: %.c
	@ mkdir -p $(@D)
	gcc $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.c: $(BUILD_DIR)/%.gz
	@ mkdir -p $(@D)
	xxd -i $< > $@ 

$(BUILD_DIR)/%.gz: $(BUILD_DIR)/%.min
	@ mkdir -p $(@D)
	gzip -c -9 $< > $@

$(BUILD_DIR)/%.min: %
	@ mkdir -p $(@D)
	minify $< -o $@

clean:
	rm -rf $(BUILD_DIR)
