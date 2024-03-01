CPPC = g++
CFLAGS = -c -Wall -fPIC -O3
BUILD_DIR = build

TARGET = 

ifeq ($(OS),Windows_NT)
TARGET = windows
else
TARGET = linux
endif

ifeq ($(TARGET),windows)
RM = del /Q
COPY = copy
SYS_FLAGS = -D _WIN32
EXE_EXTENSION = .exe
ECHO = echo
SYS_MSG = "Windows_NT detected!"
else
RM = rm -rf
COPY = cp
SYS_FLAGS = 
EXE_EXTENSION =
ECHO = echo -e
SYS_MSG = "Linux detected!"
endif

run: build
	$(BUILD_DIR)/cifs$(EXE_EXTENSION)

build: make_build_dir cifs.cpp
	$(ECHO) $(SYS_MSG)
	$(CPPC) $(CFLAGS) $(SYS_FLAGS) -I . -c cifs.cpp
	$(CPPC) -o $(BUILD_DIR)/cifs$(EXE_EXTENSION) cifs.o
	$(RM) cifs.o
ifeq ($(TARGET),linux)
	chmod +x $(BUILD_DIR)/cifs$(EXE_EXTENSION)
endif

make_build_dir:
	@mkdir $(BUILD_DIR) 2> nul || $(ECHO) > nul