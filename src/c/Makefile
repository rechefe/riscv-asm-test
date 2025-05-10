.PHONY: test build

build: build/Makefile
	@echo Build
	${MAKE} -C build

test: build
	@echo Test
	cd build; \
		ctest

build/Makefile: CMakeLists.txt
	if [ ! -d build ]; then mkdir build; fi
	cd build; \
		cmake ..

clean:
	rm -rf build