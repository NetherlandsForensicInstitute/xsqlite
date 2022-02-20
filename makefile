SHELL := /bin/bash

.PHONY: help
help:
	@echo
	@echo "makefile targets"
	@echo "----------------"
	@echo "  make wheel       - create python3 wheel"
	@echo "  make clean       - remove build data and compiled files"
	@echo "  make install     - install via pip3 (need sudo)"
	@echo "  make uninstall   - uninstall via pip3 (need sudo)"
	@echo ""

.PHONY: clean
clean:
	rm -rf xsqlite.egg-info
	rm -rf build
	rm -rf xsqlite/__pycache__
	rm -rf dist

.PHONY: install
install:
	pip3 install .

.PHONY: uninstall
uninstall:
	pip3 uninstall xsqlite

.PHONY: wheel
wheel:
	python3 setup.py bdist_wheel

