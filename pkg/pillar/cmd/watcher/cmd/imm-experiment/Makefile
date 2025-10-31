build:
	go build -o imm-experiment main.go

local-run: build
	./imm-experiment -in ../../../../../memory-monitor/results/memory_usage.csv -out ../../../../../memory-monitor/results/memory_usage_recalculated.csv
