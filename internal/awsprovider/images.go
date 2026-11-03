package cloud

import (
	"fmt"
	"strings"

	"github.com/nexusrun/korta/roles"
)

// imageSource finds an operating system's official images: the publisher's
// AWS account and a name pattern, with {arch} replaced by the publisher's
// name for the CPU architecture.
type imageSource struct {
	owner   string
	pattern string
	arch    map[string]string // EC2 architecture to the name's spelling
}

var (
	debianArch = map[string]string{"x86_64": "amd64", "arm64": "arm64"}
	rpmArch    = map[string]string{"x86_64": "x86_64", "arm64": "aarch64"}
	rhelArch   = map[string]string{"x86_64": "x86_64", "arm64": "arm64"}
)

// Accounts are the publishers' documented AMI owners: Canonical, Debian,
// Red Hat, Rocky Enterprise Software Foundation, AlmaLinux OS Foundation and
// the CentOS project. Patterns leave out minimal, Pro and BYOS images.
func imageFor(os string) (imageSource, error) {
	distro, version, err := roles.AWSRelease(os)
	if err != nil {
		return imageSource{}, err
	}
	switch distro {
	case "ubuntu":
		codename := map[string]string{"22.04": "jammy", "24.04": "noble"}[version]
		return imageSource{"099720109477", "ubuntu/images/*/ubuntu-" + codename + "-" + version + "-{arch}-server-*", debianArch}, nil
	case "debian":
		return imageSource{"136693071363", "debian-" + version + "-{arch}-*", debianArch}, nil
	case "rhel":
		return imageSource{"309956199498", "RHEL-" + version + ".*_HVM-*-{arch}-*-Hourly2-GP*", rhelArch}, nil
	case "rocky":
		return imageSource{"792107900819", "Rocky-" + version + "-EC2-Base-" + version + ".*.{arch}", rpmArch}, nil
	case "almalinux":
		return imageSource{"764336703387", "AlmaLinux OS " + version + ".* {arch}", rpmArch}, nil
	case "centos-stream":
		return imageSource{"125523088429", "CentOS Stream " + version + " {arch} *", rpmArch}, nil
	}
	return imageSource{}, fmt.Errorf("no images known for %s", os)
}

func (s imageSource) name(arch string) string {
	return strings.ReplaceAll(s.pattern, "{arch}", s.arch[arch])
}
