BUILD_DIR := build
TARGET := $(BUILD_DIR)/init
SOURCES := system/init.c system/telnet.c system/ftp.c
HEADERS := system/init.h system/telnet.h system/ftp.h

$(TARGET): $(SOURCES) $(HEADERS)
	@ mkdir -p $(@D)
	gcc -O3 -march=native -mfloat-abi=hard -mfpu=vfp $(SOURCES) -o $@

$(TARGET)_emul: $(SOURCES) $(HEADERS)
	@ mkdir -p $(@D)
	gcc -O3 -march=native -DEMUL $(SOURCES) -o $@

$(TARGET)_debug: $(SOURCES) $(HEADERS)
	@ mkdir -p $(@D)
	gcc -g -O3 -march=native -DEMUL $(SOURCES) -o $@

clean:
	rm -rf $(BUILD_DIR)