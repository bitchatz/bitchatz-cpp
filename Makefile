.PHONY: build
.DEFAULT_GOAL := help

help:
	@echo "Type: make [rule]. Available options are:"
	@echo ""
	@echo "- help"
	@echo "- format"
	@echo "- windows-format"
	@echo "- clean"
	@echo ""
	@echo "- build"
	@echo "- run"
	@echo "- run-windows"
	@echo ""

format:
	find -E src/ -regex '.*\.(cpp|hpp|cc|cxx|c|h|m|mm)' -exec clang-format -style=file -i {} \;

windows-format:
	powershell -Command "Get-ChildItem -Path src -Recurse -Include *.cpp,*.hpp,*.cc,*.cxx,*.c,*.h,*.m,*.mm | ForEach-Object { clang-format -style=file -i $$_.FullName }"

clean:
	rm -rf build
	find . -name ".DS_Store" -delete

build:
	rm -rf build
	cmake -B build .
	cmake --build build

run:
	./build/bin/bitchat

run-windows:
	powershell -Command ".\build\bin\bitchat.exe"

