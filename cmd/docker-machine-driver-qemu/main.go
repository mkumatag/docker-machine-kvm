package main

import (
	"github.com/dhiltgen/docker-machine-kvm/qemu"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(qemu.NewDriver("default", "path"))
}
