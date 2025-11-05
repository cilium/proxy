# -*- mode: ruby -*-
# vi: set ft=ruby :

$VM_MEMORY = (ENV['VM_MEMORY'] || 4096)
$VM_CPUS = (ENV['VM_CPUS'] || 4)
# Requires `vagrant plugin install vagrant-disksize`
$VM_DISK = (ENV['VM_DISK'] || "100GB")

$GO_VERSION = (ENV['GO_VERSION'] || "1.22.0")

## Some inline scripts for installation
$go_install = <<-'SCRIPT'
# Install golang
GO_VERSION=$1
curl -O https://storage.googleapis.com/golang/go$GO_VERSION.linux-amd64.tar.gz && \
    rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz \
    && rm -rf go$GO_VERSION.linux-amd64.tar.gz && \
    echo 'export PATH=$PATH:/usr/local/go/bin:/home/vagrant/go/bin' >> /home/vagrant/.bashrc
SCRIPT

# This is same as what mentioned in Docker.builder.tests
$dependencies = <<-'SCRIPT'
apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu \
      gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross binutils-x86-64-linux-gnu \
      libc6-dev \
      autoconf automake cmake coreutils curl git libtool make ninja-build patch patchelf \
      python3 python-is-python3 unzip virtualenv wget zip \
      software-properties-common && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    apt-add-repository -y "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main" && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      clang-18 clang-tools-18 lldb-18 lld-18 clang-format-18 libc++-18-dev libc++abi-18-dev && \
    apt-get purge --auto-remove && \
    apt-get clean
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.disksize.size = $VM_DISK

  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM:
    vb.memory = $VM_MEMORY
    vb.cpus = $VM_CPUS
  end
  config.vm.synced_folder ".", "/home/vagrant/proxy"

  config.vm.provision "docker"
  config.vm.provision "shell", inline: $go_install, args: $GO_VERSION
  config.vm.provision "shell", inline: $dependencies
end
