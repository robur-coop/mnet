vendors:
	test ! -d $@
	mkdir vendors
	@./source.sh

echo.hvt.target: | vendors
	@rm -f ./echo/echo.exe
	@rm -f ./echo/manifest.o
	@rm -f ./echo/manifest.c
	@echo " DESCR echo.exe"
	@dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./echo/echo.exe 1> $@ 2>&1
	@echo " BUILD echo.exe"
	@dune build --root . --profile=release ./echo/echo.exe

resolver.hvt.target: | vendors
	@rm -f ./resolver/resolver.exe
	@rm -f ./resolver/manifest.o
	@rm -f ./resolver/manifest.c
	@echo " DESCR resolver.exe"
	@dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./resolver/resolver.exe 1> $@ 2>&1
	@echo " BUILD resolver.exe"
	@dune build --root . --profile=release ./resolver/resolver.exe

echo.hvt: echo.hvt.target
	@echo " COPY echo.hvt: $(cat echo.hvt.target)"
	@cp $(file < echo.hvt.target) $@
	@chmod +w $@
	@echo " STRIP echo.hvt"
	@strip $@

resolver.hvt: resolver.hvt.target
	@echo " COPY resolver.hvt: $(cat resolver.hvt.target)"
	@cp $(file < resolver.hvt.target) $@
	@chmod +w $@
	@echo " STRIP resolver.hvt"
	@strip $@

all: echo.hvt resolver.hvt | vendors

.PHONY: clean
clean:
	if [ -d vendors ] ; then rm -fr vendors ; fi
	rm -f echo.hvt.target
	rm -f echo.hvt
	rm -f resolver.hvt.target
	rm -f resolver.hvt
