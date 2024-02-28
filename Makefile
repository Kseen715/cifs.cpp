CPPC=g++
CFLAGS = -c -Wall -fPIC -O3
build_dir=build

ifeq ($(OS),Windows_NT)
RM = del /Q
COPY = copy
SYS = -D _WIN32 -O3
EXE_EXTENSION = .exe
ECHO = echo
SYS_MSG = "Windows_NT detected!"
else
RM = rm -rf
COPY = cp
SYS = 
EXE_EXTENSION =
ECHO = echo -e
SYS_MSG = "Linux detected!"
endif

run: build
	$(build_dir)/cifs.exe

build: make_build_dir cifs.cpp
	$(ECHO) $(SYS_MSG)
	$(CPPC) $(CFLAGS) -I . -c cifs.cpp
	$(CPPC) -o $(build_dir)/cifs$(EXE_EXTENSION) cifs.o
	$(RM) cifs.o

make_build_dir:
	@mkdir $(build_dir) 2> nul || $(ECHO) > nul