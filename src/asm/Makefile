.PHONY: test

build: build/Makefile
	@echo Build
	${MAKE} -C build

test: build/Makefile build
	@echo Test
	cd build; \
		ctest

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