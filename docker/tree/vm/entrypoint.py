#!/usr/bin/env python3
#
import click
import yaml, json
import os, shutil
import uuid
import random
import socket
import pyroute2
import tempfile
import textwrap
import humanfriendly
import subprocess, sys
from urllib.parse import urlparse
import urllib.request


import logbook
logbook.StreamHandler(sys.stdout, level='INFO', bubble=True).push_application()
log = logbook.Logger(sys.argv[0])

class QemuConfig(object):
  def __init__(self):
    # Nothing
    return
  def load(self, *args):
    return
  def save(self, *args):
    return
  def prepare(self, *args):
    return
  def vendor_config(self, *args):
    return
  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    return []

class QemuStandardOpts(QemuConfig):
  qemu_executable = 'qemu-system-x86_64'
  
  static_opts = [
    '-overcommit', 'mem-lock=off',
    '-no-user-config', '-nodefaults',
    '-global', 'kvm-pit.lost_tick_policy=delay',
    '-global', 'ICH9-LPC.disable_s3=1',
    '-global', 'ICH9-LPC.disable_s4=1',
    '-no-hpet',
    '-device', 'virtio-serial',
    
    '-chardev', 'stdio,mux=on,id=char0',
    '-device', 'virtconsole,chardev=char0,name=console',
    
    '-chardev', 'socket,path=/run/qemu-serial0,server,nowait,id=char1',
    '-device', 'virtconsole,chardev=char1,name=tty',
    
    '-chardev', 'socket,path=/run/qemu-qga,server,nowait,id=qga0',
    '-device', 'virtserialport,chardev=qga0,name=org.qemu.guest_agent.0',

    '-monitor', 'unix:/run/qemu-monitor,server,nowait',
    '-device', 'virtio-balloon',
    '-device', 'virtio-rng-pci,max-bytes=1024,period=1000',
    '-fw_cfg', 'name=sysupdate,string=false',
    '-vga', 'virtio'
  ]

  def __init__(self, cpu=2, ram=2048, rtc_mode='utc', machine='q35', extra_qemu_opts=[]):
    self.cpu = cpu
    self.ram = ram
    self.guest_name = socket.gethostname()
    self.rtc_mode = rtc_mode
    self.machine = machine
    self.extra_qemu_opts = extra_qemu_opts

    self._uuid = None
    self._default_uuid = None

    # Check for KVM device
    if os.path.exists('/dev/kvm'):
      log.info('KVM support enabled')
      self.kvm = True
    else:
      log.warning('KVM support not found!')
      self.kvm = False

  @property
  def uuid(self):
    if self._uuid:
      return self._uuid
    elif not self._default_uuid:
      self._default_uuid = str(uuid.uuid4())
    return self._default_uuid
  
  @uuid.setter
  def uuid(self, value):
    self._uuid = value

  @property
  def kvm(self):
    if self._kvm:
      return [
        '-enable-kvm',
        '-cpu', 'host'        
      ]
    else:
      return []
  
  @kvm.setter
  def kvm(self, value):
    self._kvm = value
  
  # Conf
  def load(self, config):
    if 'uuid' in config['vm']:
      self.uuid = config['vm']['uuid']

  def save(self, config):
    config['vm']['uuid'] = self.uuid

  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    return [ 
      self.qemu_executable,
      "-name", f"guest={self.guest_name},debug-threads=on",
      '-rtc', f"base={self.rtc_mode},driftfix=slew",
      '-machine', f"{self.machine},dump-guest-core=off,usb=off",
      *self.static_opts,
      "-smp",   f"{self.cpu}",
      "-m",     f"{self.ram}m",
      *self.kvm,
      *self.extra_qemu_opts
    ]

class QemuDisk(QemuConfig):
  def __init__(self, path, size, index, source=None, always_pull=False, immutable=False):
    self.path = path
    self.size = size
    self.immutable = immutable
    self.index = index
    self.source = source
    self.always_pull = always_pull
  
  @property
  def immutable(self):
    if self._immutable:
      return "on"
    else:
      return "off"
  @immutable.setter
  def immutable(self, value):
    self._immutable = value

  @property
  def size(self):
    return self._size
  
  @size.setter
  def size(self, value):
    # Try to parse as integer
    if not isinstance(value, int):
      try:
        value = int(value)
      except ValueError:
        pass
    # Otherwise try to convert 1G to bytes:
    if not isinstance(value, int):
      value = humanfriendly.parse_size(value, binary=True)
    
    self._size = value

  def _create_disk(self):
    log.info(f"Create disk {self.path}: {self.size}")
    exec(['qemu-img', 'create', '-f', 'qcow2', '-o', 'cluster_size=2M', self.path, f"{self.size}"])

  def _resize_disk(self):
    log.info(f"Checking disk size: {self.path}")
    disk_info = json.loads(exec(['qemu-img', 'info', '--output=json', self.path]))
    
    # Resize if actual size is less than the wanted size
    if disk_info['virtual-size'] < self.size:
      log.info(f"Resizing the disk, current size: {disk_info['virtual-size']}, wanted size: {self.size}.")
      exec(['qemu-img', 'resize', '-f', 'qcow2', self.path, f"{self.size}"])
    elif disk_info['virtual-size'] == self.size:
      log.info(f"Disk does not require resize")
    else:
      log.warning(f"Disk wanted size is less than actual size. Disks cannot be shrunk safely, resize cancelled.")  

  def _convert_to_qcow(self):
    disk_info = json.loads(exec(['qemu-img', 'info', '--output=json', self.path]))
    if disk_info['format'] != 'qcow2':
      log.info("Converting the disk to qcow2: ")
      # Convert the image to qcow2 (cluster-size 2M)
      exec(["qemu-img", "convert", "-O", "qcow2", "-o", "cluster_size=2M", self.path, f"{self.path}.tmp"])
      os.remove(self.path)
      os.rename(f"{self.path}.tmp", self.path)
    else:
      log.info("Disk is already qcow2")

  def prepare(self):
    log.info(f"Prepare disk: {self.path}")

    # Check if image source exists
    if self.source:
      if self.always_pull:
        log.info(f"Disk{self.index} set to always_pull, pulling image:")
        _pull_disk_image(self.source, self.path)
        self._convert_to_qcow()
        self._resize_disk()
        return
      if not os.path.isfile(self.path):
        log.info(f"Disk{self.index} is missing, pulling from source:")
        _pull_disk_image(self.source, self.path)

    # Create disk if necessary
    elif not os.path.isfile(self.path):
      self._create_disk()

    if not os.path.isfile(self.path):
      raise FileNotFoundError("Source is set, but disk pull failed.")

    # Check if disk needs resize/convert
    self._convert_to_qcow()
    self._resize_disk()

  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    return [
      '-object', f'iothread,id=io{self.index}',
      '-device', f'virtio-blk-pci,drive=disk{self.index},iothread=io{self.index}',
      '-drive', f"file={self.path},if=none,snapshot={self.immutable},cache=none,id=disk{self.index},aio=native"
    ]

class QemuCDROM(QemuConfig):
  def __init__(self, path, source=None, always_pull=False):
    self.path = path
    self.source = source
    self.always_pull = always_pull
  
  def prepare(self):
    log.info(f"Prepare cdrom: {self.path}")

    # Check if image source exists
    if self.source:
      if self.always_pull:
        log.info(f"Disk set to always_pull, pulling image:")
        _pull_disk_image(self.source, self.path)
        return
      if not os.path.isfile(self.path):
        log.info(f"Disk is missing, pulling from source:")
        _pull_disk_image(self.source, self.path)
        return

    # Create disk if necessary
    if not os.path.isfile(self.path):
      raise FileNotFoundError(f"Unable to find {self.path} and source is not set")

  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    return [
      '-drive', f"file={self.path},format=raw,media=cdrom,readonly"
    ]

class QemuDiskManager(QemuConfig):
  disks = []
  root_disk_ready=False
  def __init__(self, disk_root):
    self.disk_root = disk_root
  
  def add_disk(self, size, immutable=False, source=None, always_pull=False):
    disk_path = os.path.join(self.disk_root, f"disk{len(self.disks)}.qcow2")
    disk = QemuDisk(path=disk_path, size=size, index=len(self.disks), immutable=immutable, source=source, always_pull=always_pull)
    log.info(f"Adding disk '{disk_path}' size={size}")
    self.disks.append(disk)

  def add_cdrom(self, disk_path=None, source=None, always_pull=False):
    if not disk_path:
      disk_path = os.path.join(self.disk_root, f"diskcd{len(self.disks)}.iso")
    disk = QemuCDROM(path=disk_path, source=source, always_pull=always_pull)
    log.info(f"Adding cdrom '{disk_path}'")
    self.disks.append(disk)

  def prepare(self):
    """
    Pull disk images if necessary.
    
    QemuDisk.prepare() handles pull and resize (only if required)
    """ 
    for disk in self.disks:
      disk.prepare()

  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    ret = []
    for disk in self.disks:
      ret.extend(disk.cmdline())
    return ret

class QemuNetworkInterface(QemuConfig):
  passthrough = False
  ip_addresses = None
  mtu = None
  _mac_address = None
  
  interface = None
  tap_interface = None
  br_interface = None

  routes = None
  dns_config = {
    "nameservers": [],
    "domain": '',
    "search": []
  }

  def __init__(self, interface, pcie_bus_id, pcie_bus_addr, pcie_bus_index, passthrough=False):
    self.interface = interface
    self.tap_interface = f"tap-{interface}"
    self.br_interface = f"br-{interface}"
    
    self.passthrough = passthrough
    self.pcie_bus_id = pcie_bus_id
    self.pcie_bus_addr = pcie_bus_addr
    self.pcie_bus_index = pcie_bus_index

    # Gather the routes and resolv.conf settings, for inclusion in cloud-init/metadata
    self._gather_interface_configuration()
    self._gather_routes()
    self._get_resolv_conf()
  
  def _gather_interface_configuration(self):
    ipdb = pyroute2.IPDB()
    self.ip_addresses = []

    # Gather interface config
    with ipdb.interfaces[self.interface] as i:
      if i.ipaddr:
        self.ip_addresses.append(i.ipaddr[0])
      self.mtu =  i.mtu
      #self.mac_address = i.address
  
  def _create_tap(self):
    with pyroute2.IPRoute() as ip:
      tap_exists = ip.link_lookup(ifname=self.tap_interface)
      if not tap_exists:
        log.info(f"Creating tap interface: {self.tap_interface}")
        ip.link('add', ifname=self.tap_interface, kind='tuntap', mode='tap')
        index = ip.link_lookup(ifname=self.tap_interface)[0]
        ip.link('set', index=index, state='up', mtu=self.mtu)
      else:
        log.info(f"Not re-creating tap interface: {self.tap_interface}")
    
    
  def _create_bridge(self):
    ipdb = pyroute2.IPDB()
    if not self.br_interface in ipdb.interfaces:
      log.info(f"Creating bridge: {self.br_interface}")
      with ipdb.create(kind='bridge', ifname=self.br_interface) as i:
        i.up()
        i.add_port(ipdb.interfaces[self.tap_interface])
        i.add_port(ipdb.interfaces[self.interface])
    else:
      log.info(f"Not re-creating bridge: {self.br_interface}")

  
  def _flush_ip_addresses(self):
    """
    Delete all IP addresses from the interface.
    """
    log.debug(f"Removing all addresses from {self.interface}")
    ipdb = pyroute2.IPDB()
    with ipdb.interfaces[self.interface] as i:
      for addr in i.ipaddr:
        i.del_ip(*addr)
  
  @property
  def mac_address(self):
    if not self._mac_address:
      log.debug(f"{self.interface}: no mac address is set, generating a random one.")
      self._mac_address = self.__new_random_mac()
    return self._mac_address
  
  @mac_address.setter
  def mac_address(self, val):
    self._mac_address = val

  def __new_random_mac(self):
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    
  @property
  def network_config(self):
    if self.passthrough:
      addresses = []
      for addr in self.ip_addresses:
        addresses.append(f"{addr['address']}/{addr['prefixlen']}")
      
      return {
        "version": 2,
        "ethernets": {
          self.interface: {
            "match": {
              "macaddress": self.mac_address
            },
            "addresses": addresses,
            "nameservers": {
              "addresses": self.dns_config['nameservers'],
              "search": self.dns_config['search']
            },
            "routes": self.routes
          }
        }
      }
    else:
      return None

  def _get_resolv_conf(self):
    self.dns_config['nameservers'] = []
    self.dns_config['domain'] = ''
    self.dns_config['search'] = []
    with open('/etc/resolv.conf', 'r') as stream:
      for l in stream:
        if len(l) == 0 or l[0] == '#' or l[0] == ';':
          continue

        tokens = l.split()
        if len(tokens) < 2:
          continue

        if tokens[0] == 'nameserver':
          self.dns_config['nameservers'].append(tokens[1])
        elif tokens[0] == 'domain':
          self.dns_config['domain'] = tokens[1]
        elif tokens[0] == 'search':
          for suffix in tokens[1:]:
            self.dns_config['search'].append(suffix)
    
  def _gather_routes(self):
    ipdb = pyroute2.IPDB()
    self.routes = []

    # Gather routes
    for route in ipdb.routes:
      if route['dst'] == 'default':
        dst = '0.0.0.0/0'
      else:
        dst = route['dst']
      
      if not route['gateway']:
        self.routes.append(
          { "to": dst, "scope": "link"}
        )
      else:
        self.routes.append(
          { "to": dst, "via": route['gateway']}
        )


  def load(self, config):
    if self.interface not in config['vm']['network']:
      # Property will auto-generate this for us:
      log.info(f"Generated new mac for {self.interface}: {self.mac_address}")
    else:
      self.mac_address = config['vm']['network'][self.interface]['mac_address']
      log.debug(f"Loaded mac for {self.interface}: {self.mac_address} from config")

  def save(self, config):
    if self.mac_address:
      config['vm']['network'][self.interface] = { "mac_address": self.mac_address }

  def prepare(self):
    self._create_tap()
    self._create_bridge()
    if self.passthrough:
      self._flush_ip_addresses()

  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    
    if self.pcie_bus_index == 0:
      cmdline = ['-device', f"pcie-root-port,id={self.pcie_bus_id}.{self.pcie_bus_index},bus=pcie.0,chassis={self.pcie_bus_index + 1},addr={self.pcie_bus_addr}.{self.pcie_bus_index},multifunction=on" ]
    else:
      cmdline = ['-device', f"pcie-root-port,id={self.pcie_bus_id}.{self.pcie_bus_index},bus=pcie.0,chassis={self.pcie_bus_index + 1},addr={self.pcie_bus_addr}.{self.pcie_bus_index}" ]

    cmdline.extend(
      [
        '-netdev', f"tap,vhost=on,script=no,downscript=no,ifname={self.tap_interface},id={self.interface}",
        '-device', f"virtio-net-pci,host_mtu={self.mtu},mac={self.mac_address},netdev={self.interface},bus={self.pcie_bus_id}.{self.pcie_bus_index}"
      ]
    )
    return cmdline

class QemuNetworkManager(QemuConfig):
  networks = []
  network_config = None
  pcie_bus_id = "rp0"
  pcie_bus_addr = "0x14"

  def __init__(self, passthrough_first_nic=False):
    self.passthrough_first_nic = passthrough_first_nic

  def add_network(self, interface):
    passthrough=False
    if self.passthrough_first_nic and len(self.networks) < 1:
      passthrough=True

    network = QemuNetworkInterface(interface=interface, passthrough=passthrough, pcie_bus_id=self.pcie_bus_id, pcie_bus_addr=self.pcie_bus_addr, pcie_bus_index=len(self.networks))
    
    log.info(f"Adding network '{interface}' fn={len(self.networks)} passthrough={passthrough}")
    self.networks.append(network)

  def load(self, config):
    for network in self.networks:
      network.load(config)
  
  def save(self, config):
    for network in self.networks:
      network.save(config)

  def prepare(self):
    """
    Configure each network's bridge, tap, firewalls, etc.
    """
    for network in self.networks:
      network.prepare()
      if network.passthrough:
        self.network_config = network.network_config      

  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    cmdline = []
    for network in self.networks:
      cmdline.extend(network.cmdline())
    return cmdline

class QemuConfigDrive(QemuConfig):
  def __init__(self, path, user_data_path=[], instance_secret_keys=[], network_manager=None):
    self.path = path
    self.user_data_path = user_data_path
    self.network_manager = network_manager
    self.instance_secret_keys = instance_secret_keys

  def prepare(self):
    log.info("Generating config drive:")
    with tempfile.TemporaryDirectory() as tempdir:
      if self.user_data_path:
        with open(os.path.join(tempdir, 'user-data'), 'w') as outfile:
          for user_data_file in self.user_data_path:
            log.debug(f"Found user-data at {self.user_data_path}")
            with open(user_data_file) as infile:
              for line in infile:
                outfile.write(line)
      
      # Passthrough for secrets-ey-stuff
      instance_metadata = {
        "instance-id": socket.gethostname(),
        "secrets": {}
      }
      
      for key in self.instance_secret_keys:
        if key in os.environ:
          log.debug(f"Passing through secret from environment: {key}=<hidden>")
          instance_metadata['secrets'][key] = os.environ[key]
        else:
          log.warning(f"Environment variable '{key}' does not exist.")

      with open(os.path.join(tempdir, 'meta-data'), 'w') as stream:
        yaml.safe_dump(instance_metadata, stream)
      log.debug(f"meta-data:\n{instance_metadata}")

      vendor_data = {
        "hostname": instance_metadata['instance-id'],
      }
      with open(os.path.join(tempdir, 'vendor-data'), 'w') as stream:
        stream.write("#cloud-config\n")
        yaml.safe_dump(vendor_data, stream)
      log.debug(f"vendor-data:\n{vendor_data}")


      if self.network_manager and self.network_manager.network_config:
        with open(os.path.join(tempdir, 'network-config'), 'w') as stream:
          yaml.safe_dump(self.network_manager.network_config, stream)
        log.debug(f"network-config:\n{self.network_manager.network_config}")
      else:
        log.debug(f"network-config: None")

      # Create the configdrive ISO
      exec(
        ['mkisofs', '-output', self.path, '-volid', 'cidata', '-joliet', '-rock', '.'],
        cwd=tempdir,
        shell=True
      )

  def cmdline(self):
    log.debug(f"{self.__class__.__name__}: generating cmdline")
    return [
      '-drive', f"file={self.path},format=raw,media=cdrom,readonly"
    ]

class PersistentConfig():
  # Default config:
  config = { "vm": { "network": {} } }

  def __init__(self, config_path):
    self.config_path = config_path

  def __enter__(self):
    self._load()
    return self
  
  def __exit__(self, exc_type, exc_val, exc_tb):
    self._save()
  
  
  def _load(self):
    # Read the config as YAML, if it exists
    if os.path.isfile(self.config_path):
      log.info(f"Loading configuration from {self.config_path}")
      with open(self.config_path, 'r') as stream:
        try:
          self.config = yaml.safe_load(stream)
        except yaml.YAMLError:
          log.error(f"Unable to load VM config from {self.config_path}:")
          raise
    else:
      log.info(f"Configuration is blank, creating a new configuration")

  def _save(self):
    # Write back the new configuration
    log.info("Persisting config.")
    with open(self.config_path, 'w') as stream:
      try:
        yaml.dump(self.config, stream, default_flow_style=False)
      except yaml.YAMLError:
        log.error(f"Failed to write persistent configuration to {self.config_path}")
        raise

  def load_config(self, classes):
    for arg in classes:
      arg.load(self.config)

  def save_config(self, classes):
    for arg in classes:
      arg.save(self.config)


# TODO: Utility class this?
def _pull_disk_image(image_source, image_dest):
  log.info(f"Pulling disk image: {image_source}")
  # Determine how to pull this image:
  image_source_path = urlparse(image_source)
  if image_source_path.scheme.lower() in ('s3', 's3s'):
    _pull_disk_image_s3(image_source_path, image_dest)
  elif image_source_path.scheme.lower() in ('http', 'https'):
    _pull_disk_image_http(image_source, image_dest)
  else:
    raise ValueError(f"Unsupported scheme ({image_source_path.scheme}) for image_source: {image_source}")


def _pull_disk_image_http(image_source, image_dest):
  urllib.request.urlretrieve(image_source, image_dest)

def _pull_disk_image_s3(image_source, image_dest):
  scheme = image_source.scheme.replace('s3', 'http')
  image_host = f"{scheme}://{image_source.netloc}"

  env = { "MC_HOST_src": image_host }
  exec(['mc', '-q', 'cp', f"src{image_source.path}", image_dest], custom_env=env)


def exec(cmd, custom_env={}, cwd=None, shell=False):
    os_env = dict(os.environ)
    env = { **os_env, **custom_env }
    if not cwd:
      cwd = os.getcwd()

    log.debug(f"Executing command: {cmd}")
    log.debug(f"With environment: {env}")
    log.debug(f"In directory: {cwd}")
    try:
      output = subprocess.check_output(
        cmd,
        env=env,
        cwd=cwd,
        stderr=subprocess.STDOUT
      )
      log.info(output)
      return output
    except subprocess.CalledProcessError as exc:
      log.error("Failed to run command:", cmd)
      log.error(exc.output)
      raise


@click.command()
@click.option('--machine', default='q35', type=str, help="Machine type")
@click.option('--cpu', default="2", type=str, help="CPU's assigned to the VM")
@click.option('--ram', default=2048, help="RAM assigned to the VM (in MB)")
@click.option('--nic','nics', multiple=True, help="Network Cards to Bridge to the VM (can be used multiple times)", default=['eth0'])
@click.option('--disk', 'disks', multiple=True, help="Disks to provide to the VM (--disk size=20G,source=src.com/x,immutable,always_pull)", default=['size=20G'])
@click.option('--cdrom', 'cdroms', multiple=True, help="ISO's to provide to the VM (--cdrom source=src.com/x,always_pull)")
@click.option('--passthrough-first-nic', type=bool, is_flag=True, default=False, help="Passthrough the first NIC's IP address from the command line.")
@click.option('--vnc-port', type=int, default=None, help="VNC Port to use for remote console (this will be redirected in the container)")
@click.option('--extra-qemu-arg', 'extra_qemu_args', multiple=True, help="Additional arguments to add to QEMU commandline")

@click.option('--vm-data',
  type=click.Path(exists=True, file_okay=False, writable=True, resolve_path=True),
  default='/vm/data',
  help="Path to store VM data")

@click.option('--config', 'config_path', 
  type=click.Path(exists=False, dir_okay=False, writable=True, resolve_path=True),
  default='/vm/data/config.yaml',
  help="Persistent VM configuration storage path")

@click.option('--user-data', 
  type=click.Path(exists=True, dir_okay=False, resolve_path=True), 
  multiple=True,
  help='Path to user-data (multiple will be concatenated, in order)')

@click.option('--instance-secret-key',
  type=str, multiple=True,
  help='Retrieve metadata from environment variable. Metadata is available under ds.meta_data.secrets.<key-name> key in cloud-init')

@click.option('--debug', type=bool, is_flag=True, default=False, help="Enable debug logging")
@click.option('--test', type=bool, is_flag=True, default=False, help="Don't actually execute the VM")
def run(machine, cpu, ram, nics, disks, cdroms, vm_data, passthrough_first_nic, vnc_port, extra_qemu_args, config_path, user_data, instance_secret_key, test, debug):
  # Runs a VM, generating and persisting configurations as necessary
  if debug:
    logbook.StreamHandler(sys.stdout, level='DEBUG').push_application()
    log.debug("Debug logging enabled")

  # qemu-cmdline
  qemu_cmdline = []

  # Create the configuration object
  with PersistentConfig(config_path) as config:
    qemu_options = [
      QemuStandardOpts(cpu=cpu, ram=ram, machine=machine, extra_qemu_args=extra_qemu_args),
    ]
    
    # Add disks
    vmdisks = QemuDiskManager(disk_root=vm_data)
    for disk in disks:
      size='5G'
      source=None
      always_pull=False
      immutable=False
      disk_props = disk.split(',')
      for prop in disk_props:
        if 'size=' in prop:
          size=prop.replace('size=','')
        if 'source=' in prop:
          source=prop.replace('source=','')
        if 'always_pull' in prop:
          log.info(f"Disk image will always_pull")
          always_pull=True
        if 'immutable' in prop:
          log.info(f"Disk image is immutable")
          immutable=True
        
      vmdisks.add_disk(size=size, immutable=immutable, source=source, always_pull=always_pull)

    for cdrom in cdroms:
      source=None
      always_pull=False
      disk_props = cdrom.split(',')
      for prop in disk_props:
        if 'source=' in prop:
          source=prop.replace('source=','')
        if 'always_pull' in prop:
          always_pull=True
      vmdisks.add_cdrom(source=source, always_pull=always_pull)
      

    qemu_options.append(vmdisks)

    # Add networks
    networks = QemuNetworkManager(passthrough_first_nic=passthrough_first_nic)
    for nic in nics:
      networks.add_network(interface=nic)
    qemu_options.append(networks)
    
    # Create the config-drive
    qemu_options.append(QemuConfigDrive(path=os.path.join(vm_data, 'config.iso'), instance_secret_keys=instance_secret_key, user_data_path=user_data, network_manager=networks))
    
    # Configure each class, if needed:
    config.load_config(qemu_options)

    # Prepare disks, networks, defaults, etc:
    for option in qemu_options:
      option.prepare()

    for option in qemu_options:
      qemu_cmdline.extend(option.cmdline())
    
    # Pull configs back into the Persistence class
    config.save_config(qemu_options)

    # Delete the qemu_options reference - not sure if python will just stay in ram after we exec() to qemu
    del(qemu_options)
    del(disks)

  # cmdline
  log.debug("Command line: \n")
  log.debug("\n".join(qemu_cmdline))

  if not test:
    os.execvp('qemu-system-x86_64', qemu_cmdline)

if __name__ == '__main__':
  # pylint: disable=no-value-for-parameter,unexpected-keyword-arg
  run(auto_envvar_prefix='VM')
