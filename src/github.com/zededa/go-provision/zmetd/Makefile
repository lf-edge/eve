TARGET = zmetd

GO = go
SRCS = zmetrics.go
PROTOBUF_FILE = zmet.proto
PROTOBUF_OBJS = zmet/zmet.pb.go

all: $(TARGET)

$(TARGET): $(SRCS) $(PROTOBUF_OBJS)
	$(GO) build -o $@ $(SRCS)

$(PROTOBUF_OBJS): $(PROTOBUF_FILE)
	mkdir -p $(basename $(PROTOBUF_FILE))
	protoc --go_out=$(basename $(PROTOBUF_FILE)) $(PROTOBUF_FILE)

clean:
	rm -rf $(TARGET) $(basename $(PROTOBUF_FILE))
