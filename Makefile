# Makefile para compilar ML-DSA, XMSS y SLH-DSA

INCLUDE ?= /usr/local/include/botan-3
LIB ?= /usr/local/lib

CXX = g++
CXXFLAGS = -std=c++20 -I$(INCLUDE)
LDFLAGS = -L$(LIB) -lbotan-3

BINARIES = ML-DSA XMSS SLH-DSA

all: $(BINARIES)
	@echo "Compilación completada."
	@echo "\n[!]Si al ejecutar ves un error como:"
	@echo "     error while loading shared libraries: libbotan-3.so..."
	@echo "   prueba esto:"
	@echo "     export LD_LIBRARY_PATH=$(LIB):\$$LD_LIBRARY_PATH"

ML-DSA: ml-dsa.cpp
	$(CXX) $(CXXFLAGS) $< $(LDFLAGS) -o $@

XMSS: xmss.cpp
	$(CXX) $(CXXFLAGS) $< $(LDFLAGS) -o $@

SLH-DSA: slh-dsa.cpp
	$(CXX) $(CXXFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f $(BINARIES)
