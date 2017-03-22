default: build

build:
	GOOS=darwin GOARCH=amd64 GOGC=off go build -o darwin/docker-machine-driver-qemu
	GOOS=linux GOARCH=amd64 GOGC=off go build -o linux/docker-machine-driver-qemu
