// +build darwin

package qemu

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

const (
	connectionString   = "qemu:///system"
	privateNetworkName = "docker-machines"
	isoFilename        = "boot2docker.iso"
	dnsmasqLeases      = "/var/lib/libvirt/dnsmasq/%s.leases"
	dnsmasqStatus      = "/var/lib/libvirt/dnsmasq/%s.status"

	tapupTemplate = `#!/bin/sh
TAPDEV="$1"
BRIDGEDEV='{{.Network}}'
ifconfig $BRIDGEDEV addm $TAPDEV
#ip link set $TAPDEV master $BRIDGEDEV
`
	tapdownTemplate = `#!/bin/sh
TAPDEV="$1"
BRIDGEDEV='{{.Network}}'
ifconfig $BRIDGEDEV deletem $TAPDEV
#ip link set dev $TAPDEV nomaster
`
)

type Driver struct {
	*drivers.BaseDriver

	command_arp    string
	MACaddr        string
	DomainType     string
	Arch           string
	CPUtype        string
	CdDeviceName   string
	CdBusType      string
	DiskDeviceName string
	DiskBusType    string
	Memory         int
	DiskSize       int
	CPU            int
	Network        string
	PrivateNetwork string
	ISO            string
	Boot2DockerURL string
	CaCertPath     string
	PrivateKeyPath string
	DiskPath       string
	CacheMode      string
	IOMode         string
	Tapscriptup    string
	Tapscriptdown  string
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:  "qemu-arch",
			Usage: "Architecture of domain",
			Value: "x86_64",
		},
		mcnflag.IntFlag{
			Name:  "qemu-memory",
			Usage: "Size of memory for host in MB",
			Value: 1024,
		},
		mcnflag.IntFlag{
			Name:  "qemu-disk-size",
			Usage: "Size of disk for host in MB",
			Value: 20000,
		},
		mcnflag.IntFlag{
			Name:  "qemu-cpu-count",
			Usage: "Number of CPUs",
			Value: 1,
		},
		// TODO - support for multiple networks
		mcnflag.StringFlag{
			Name:  "qemu-network",
			Usage: "Name of network to connect to",
			Value: "bridge0",
		},
		mcnflag.StringFlag{
			EnvVar: "KVM_BOOT2DOCKER_URL",
			Name:   "qemu-boot2docker-url",
			Usage:  "The URL of the boot2docker image. Defaults to the latest available version",
			Value:  "",
		},
		mcnflag.StringFlag{
			Name:  "qemu-cache-mode",
			Usage: "Disk cache mode: default, none, writethrough, writeback, directsync, or unsafe",
			Value: "default",
		},
		mcnflag.StringFlag{
			Name:  "qemu-io-mode",
			Usage: "Disk IO mode: threads, native",
			Value: "threads",
		},
		/* Not yet implemented
		mcnflag.Flag{
			Name:  "qemu-no-share",
			Usage: "Disable the mount of your home directory",
		},
		*/
	}
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHKeyPath() string {
	return d.ResolveStorePath("id_rsa")
}

func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = 22
	}

	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "root"
	}

	return d.SSHUser
}

func (d *Driver) DriverName() string {
	return "qemu"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	log.Debugf("SetConfigFromFlags called")
	d.Arch = flags.String("qemu-arch")
	d.Memory = flags.Int("qemu-memory")
	d.DiskSize = flags.Int("qemu-disk-size")
	d.CPU = flags.Int("qemu-cpu-count")
	d.Network = flags.String("qemu-network")
	d.Boot2DockerURL = flags.String("qemu-boot2docker-url")
	d.CacheMode = flags.String("qemu-cache-mode")
	d.IOMode = flags.String("qemu-io-mode")
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")
	d.SwarmDiscovery = flags.String("swarm-discovery")
	d.ISO = d.ResolveStorePath(isoFilename)
	d.SSHUser = "root"
	d.SSHPort = 22
	d.DiskPath = d.ResolveStorePath(fmt.Sprintf("%s.img", d.MachineName))
	d.Tapscriptup = d.ResolveStorePath("tap-up")
	d.Tapscriptdown = d.ResolveStorePath("tap-down")
	return nil
}

func (d *Driver) GetURL() (string, error) {
	log.Debugf("GetURL called")
	ip, err := d.GetIP()
	if err != nil {
		log.Warnf("Failed to get IP: %s", err)
		return "", err
	}
	if ip == "" {
		return "", nil
	}
	return fmt.Sprintf("tcp://%s:2376", ip), nil // TODO - don't hardcode the port!
}

func (d *Driver) PreCreateCheck() error {
	// TODO We could look at conn.GetCapabilities()
	// parse the XML, and look for kvm
	log.Debug("About to check libvirt version")

	return nil
}

func (d *Driver) Create() error {
	b2dutils := mcnutils.NewB2dUtils(d.StorePath)
	if err := b2dutils.CopyIsoToMachineDir(d.Boot2DockerURL, d.MachineName); err != nil {
		return err
	}

	log.Infof("Creating SSH key...")
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	if err := os.MkdirAll(d.ResolveStorePath("."), 0755); err != nil {
		return err
	}

	// Libvirt typically runs as a deprivileged service account and
	// needs the execute bit set for directories that contain disks
	for dir := d.ResolveStorePath("."); dir != "/"; dir = filepath.Dir(dir) {
		log.Debugf("Verifying executable bit set on %s", dir)
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		mode := info.Mode()
		if mode&0001 != 1 {
			log.Debugf("Setting executable bit set on %s", dir)
			mode |= 0001
			os.Chmod(dir, mode)
		}
	}

	log.Debugf("Creating VM data disk...")
	if err := d.generateDiskImage(d.DiskSize); err != nil {
		return err
	}

	var err error

	d.MACaddr, err = generateMAC()
	if err != nil {
		return err
	}

	log.Infof("Starting QEMU VM...")

	if err := d.Start(); err != nil {
		return err
	}
	log.Infof("Returned TO Create")
	return nil
}

func (d *Driver) Start() error {
	log.Debugf("Starting VM %s", d.MachineName)
	startCmd := []string{
		"-net", "nic,model=virtio",
		"-m", "4G,slots=32,maxmem=32G",
		"-cdrom", "boot2docker.iso",
		"-net nic,model=virtio",
		"-net tap,script=./tap-up,downscript=./tap-down",
		"-cpu", "POWER8",
		"--nographic",
		"-vga", "none",
		"-machine", "pseries,accel=tcg",
	}

	if stdout, stderr, err := d.cmdOutErr("qemu-system-ppc64", startCmd...); err != nil {
		fmt.Printf("OUTPUT: %s\n", stdout)
		fmt.Printf("ERROR: %s\n", stderr)
		return err
	}

	// They wont start immediately
	time.Sleep(120 * time.Second)
	for i := 0; i < 60; i++ {
		time.Sleep(time.Second)
		ip, _ := d.GetIP()
		if ip != "" {
			// Add a second to let things settle
			time.Sleep(time.Second)
			log.Infof("system is up. connect to docker on tcp://%s:2376", ip)
			return nil
		}
		log.Debugf("IP is %v", ip)
		log.Debugf("Waiting for the VM to come up... %d", i)
	}
	log.Warnf("Unable to determine VM's IP address, did it fail to boot?")
	return nil
}

func (d *Driver) cmdOutErr(cmdStr string, args ...string) (string, string, error) {
	log.Debugf("executing: %v %v", cmdStr, strings.Join(args, " "))

	var stdout_tap bytes.Buffer
	var stderr_tap bytes.Buffer

	log.Debugf("Creating Tap scripts for %s %s", d.Tapscriptup, d.Tapscriptdown)
	os.Create(d.Tapscriptup)
	os.Create(d.Tapscriptdown)

	var file, err_up = os.OpenFile(d.Tapscriptup, os.O_RDWR, 0777)
	if err_up != nil {
		log.Debugf("File creation failed")
		return stdout_tap.String(), stderr_tap.String(), err_up
	}

	var file_down, err_down = os.OpenFile(d.Tapscriptdown, os.O_RDWR, 0777)

	if err_down != nil {
		log.Debugf("File creation failed")
		return stdout_tap.String(), stderr_tap.String(), err_down
	}

	tmpl, err := template.New("tapup").Parse(tapupTemplate)
	if err != nil {
		return "", "", err
	}
	var tapup bytes.Buffer
	err = tmpl.Execute(&tapup, d)
	if err != nil {
		return "", "", err
	}
	_, err_up = file.WriteString(tapup.String())

	tmpl, err = template.New("tapup").Parse(tapdownTemplate)
	if err != nil {
		return "", "", err
	}
	var tapdown bytes.Buffer
	err = tmpl.Execute(&tapdown, d)
	if err != nil {
		return "", "", err
	}
	_, err_up = file_down.WriteString(tapdown.String())

	os.Chmod(d.Tapscriptdown, 0777)
	os.Chmod(d.Tapscriptup, 0777)

	err_up = file.Sync()
	err_down = file_down.Sync()
	file.Close()
	file_down.Close()

	var command string = fmt.Sprintf("qemu-system-ppc64 -cpu POWER8 --nographic -vga none -machine pseries,accel=tcg -m 3G,slots=32,maxmem=32G -cdrom %s -qmp unix:%s,server,nowait -drive file=%s,if=none,id=drive-virtio-disk0,format=raw,cache=none -device virtio-blk-pci,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0 -net nic,model=virtio,macaddr=%s -net user -net tap,script=%s,downscript=%s", d.ISO, d.monitorPath(), d.DiskPath, d.MACaddr, d.Tapscriptup, d.Tapscriptdown)

	parts := strings.Fields(command)
	head := parts[0]
	parts = parts[1:len(parts)]
	cmd := exec.Command(head, parts...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	log.Debug(cmd)
	err = cmd.Start()
	stderrStr := stderr.String()
	log.Debugf("STDERR: %#v", err)
	if err != nil {
		if ee, ok := err.(*exec.Error); ok && ee == exec.ErrNotFound {
			err = fmt.Errorf("Mystery!")
		}
	} else {
		// also catch error messages in stderr, even if the return code
		// looks OK
		if strings.Contains(stderrStr, "error:") {
			err = fmt.Errorf("%v %v failed: %v", cmdStr, strings.Join(args, " "), stderrStr)
		}
	}
	//	if err = cmd.Wait(); err != nil {
	//		log.Debugf("Command finished with error: %#v", err)
	//		return stdout.String(), stderrStr, err
	//	}

	return stdout.String(), stderrStr, err
}

func cmdStart(cmdStr string, args ...string) error {
	cmd := exec.Command(cmdStr, args...)
	log.Debugf("executing: %v %v", cmdStr, strings.Join(args, " "))
	return cmd.Start()
}

func (d *Driver) Stop() error {
	// _, err := d.RunQMPCommand("stop")
	_, err := d.RunQMPCommand("system_powerdown")
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Remove() error {
	log.Debugf("executing Remove")

	s, _ := d.GetState()
	if s == state.Running {
		d.Kill()
	}
	_, err := d.RunQMPCommand("quit")
	if err != nil {
		//return err
	}
	return nil
}

func (d *Driver) Restart() error {
	s, err := d.GetState()
	if err != nil {
		return err
	}

	if s == state.Running {
		if err := d.Stop(); err != nil {
			return err
		}
	}
	return d.Start()
}

func (d *Driver) Kill() error {
	// _, err := d.RunQMPCommand("quit")
	_, err := d.RunQMPCommand("system_powerdown")
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) GetState() (state.State, error) {
	ret, err := d.RunQMPCommand("query-status")

	if ret == nil {
		return state.Stopped, nil
	}

	if err != nil {
		log.Debugf("Error is %s", err)
		//return state.Error, err
	}
	// RunState is one of:
	// 'debug', 'inmigrate', 'internal-error', 'io-error', 'paused',
	// 'postmigrate', 'prelaunch', 'finish-migrate', 'restore-vm',
	// 'running', 'save-vm', 'shutdown', 'suspended', 'watchdog',
	// 'guest-panicked'
	switch ret["status"] {
	case "running":
		return state.Running, nil
	case "paused":
		return state.Paused, nil
	case "shutdown":
		return state.Stopped, nil
	}
	return state.None, nil
}

func (d *Driver) GetIP() (string, error) {
	// DHCP is used to get the IP, so qemu hosts don't have IPs unless
	// they are running
	log.Debugf("Splitting MAC")
	s_mac := strings.Split(d.MACaddr, ":")
	for i := 0; i < len(s_mac); i += 1 {
		if s_mac[i][0:1] == "0" {
			s_mac[i] = s_mac[i][1:2]
		}
	}
	res := strings.Join(s_mac, ":")
	var command string = fmt.Sprintf("arp -a| grep %s|cut -d ' ' -f 2|sed 's/)//' |sed 's/(//'", res)
	log.Debugf("GetIP command %s", command)
	result, err := exec.Command("bash", "-c", command).Output()
	log.Debugf("GetIP: %s", result)
	if err != nil {
		return strings.TrimSpace(string(result)), fmt.Errorf("Error getting IP: %s", err)
	}
	log.Debugf("GetIP: resulting ip is:", strings.TrimSpace(strings.Replace(string(result), " ", "", -1)))

	if result != nil {
		return strings.Replace(strings.Replace(string(result), " ", "", -1), "\n", "", -1), nil
	}

	log.Debugf("GetIP: IP not found. Try again")
	return "", nil

	log.Debugf("GetIP checking IP")
	s, err := d.GetState()
	if err != nil {
		return "", err
	}
	if s != state.Running {
		return "", drivers.ErrHostIsNotRunning
	}
	return "", nil
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

// Make a boot2docker VM disk image.
func (d *Driver) generateDiskImage(size int) error {
	log.Debugf("Creating %d MB hard disk image...", size)

	magicString := "boot2docker, please format-me"

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	// magicString first so the automount script knows to format the disk
	file := &tar.Header{Name: magicString, Size: int64(len(magicString))}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	if _, err := tw.Write([]byte(magicString)); err != nil {
		return err
	}
	// .ssh/key.pub => authorized_keys
	file = &tar.Header{Name: ".ssh", Typeflag: tar.TypeDir, Mode: 0700}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	pubKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}
	file = &tar.Header{Name: ".ssh/authorized_keys", Size: int64(len(pubKey)), Mode: 0644}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	if _, err := tw.Write([]byte(pubKey)); err != nil {
		return err
	}
	file = &tar.Header{Name: ".ssh/authorized_keys2", Size: int64(len(pubKey)), Mode: 0644}
	if err := tw.WriteHeader(file); err != nil {
		return err
	}
	if _, err := tw.Write([]byte(pubKey)); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	raw := bytes.NewReader(buf.Bytes())
	log.Debugf("diskpath is %s", d.DiskPath)
	return createDiskImage(d.DiskPath, size, raw)
}

// createDiskImage makes a disk image at dest with the given size in MB. If r is
// not nil, it will be read as a raw disk image to convert from.
func createDiskImage(dest string, size int, r io.Reader) error {
	// Convert a raw image from stdin to the dest VMDK image.
	sizeBytes := int64(size) << 20 // usually won't fit in 32-bit int (max 2GB)
	f, err := os.Create(dest)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, r)
	if err != nil {
		return err
	}
	// Rely on seeking to create a sparse raw file for qemu
	f.Seek(sizeBytes-1, 0)
	f.Write([]byte{0})
	return f.Close()
}

// Generates random mac address
func generateMAC() (string, error) {
	macbuf := make([]byte, 6)
	if _, err := rand.Read(macbuf); err != nil {
		return "", err
	}
	// Set the local bit
	macbuf[0] = (macbuf[0] | 2) & 0xfe
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x\n", macbuf[0], macbuf[1], macbuf[2], macbuf[3], macbuf[4], macbuf[5]), nil
}

func (d *Driver) monitorPath() string {
	return filepath.Join(d.StorePath, "monitor")
}

func (d *Driver) RunQMPCommand(command string) (map[string]interface{}, error) {
	// connect to monitor
	conn, err := net.Dial("unix", d.monitorPath())
	if err != nil {
		log.Debugf("Connect failed")
		return nil, err
	}
	defer conn.Close()

	// initial QMP response
	var buf [1024]byte
	nr, err := conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	type qmpInitialResponse struct {
		QMP struct {
			Version struct {
				QEMU struct {
					Micro int `json:"micro"`
					Minor int `json:"minor"`
					Major int `json:"major"`
				} `json:"qemu"`
				Package string `json:"package"`
			} `json:"version"`
			Capabilities []string `json:"capabilities"`
		} `jason:"QMP"`
	}

	var initialResponse qmpInitialResponse
	json.Unmarshal(buf[:nr], &initialResponse)

	// run 'qmp_capabilities' to switch to command mode
	// { "execute": "qmp_capabilities" }
	type qmpCommand struct {
		Command string `json:"execute"`
	}
	jsonCommand, err := json.Marshal(qmpCommand{Command: "qmp_capabilities"})
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(jsonCommand)
	if err != nil {
		return nil, err
	}
	nr, err = conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	type qmpResponse struct {
		Return map[string]interface{} `json:"return"`
	}
	var response qmpResponse
	err = json.Unmarshal(buf[:nr], &response)
	if err != nil {
		return nil, err
	}
	// expecting empty response
	if len(response.Return) != 0 {
		return nil, fmt.Errorf("qmp_capabilities failed: %v", response.Return)
	}

	// { "execute": command }
	jsonCommand, err = json.Marshal(qmpCommand{Command: command})
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(jsonCommand)
	if err != nil {
		return nil, err
	}
	nr, err = conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(buf[:nr], &response)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(command, "query-") {
		return response.Return, nil
	}
	// non-query commands should return an empty response
	if len(response.Return) != 0 {
		return nil, fmt.Errorf("%s failed: %v", command, response.Return)
	}
	return response.Return, nil
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return &Driver{
		PrivateNetwork: privateNetworkName,
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}
