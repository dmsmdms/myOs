BUILD_DIR := build
TARGET := $(BUILD_DIR)/init
SOURCE := system/init.c system/telnet.c system/ftp.c

$(TARGET):
	@ mkdir -p $(@D)
	arm-linux-gnueabihf-gcc -O3 -marm -mcpu=arm1176jzf-s -mfloat-abi=hard -mfpu=vfp $(SOURCE) -o $@

$(TARGET)_emul:
	@ mkdir -p $(@D)
	gcc -O3 -march=native $(SOURCE) -o $@

clean:
	rm -rf $(BUILD_DIR)