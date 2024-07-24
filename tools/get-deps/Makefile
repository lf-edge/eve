SOURCES=main.go
MODULES=go.mod go.sum
EXECUTABLE=get-deps

.PHONY: clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES) $(MODULES)
	go mod tidy
	go mod vendor
	CGO_ENABLED=0 go build -o $(EXECUTABLE) $(SOURCES)

clean:
	rm -f $(EXECUTABLE)

