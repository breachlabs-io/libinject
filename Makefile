.PHONY: build

build: .setup-cmake
	make -C build/

release: .setup-cmake-release
	make -C build/

clean: .setup-cmake
	make -C build/ clean

.setup-cmake:
	cmake -B build/ .

.setup-cmake-release:
	cmake -B build/ -DCMAKE_BUILD_TYPE=Release