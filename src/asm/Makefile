.PHONY: test build

build: build/Makefile
	@echo Build
	${MAKE} -C build

setup: build/Makefile

build/Makefile: CMakeLists.txt cmake/riscv.cmake
	if [ ! -d build ]; then mkdir build; fi
	cd build; \
		cmake \
			-G "Unix Makefiles" \
				-DCMAKE_TOOLCHAIN_FILE=../cmake/riscv.cmake \
			..

clean:
	rm -rf build