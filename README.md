# Docker QEMU VM

## Intro
This is a qemu-vm inside a docker container, for use with my Kubernetes cluster at home.

The entrypoint script sets up the necessary tap interfaces and bridges for each network interface you specify (defaults to eth0). Additionally, you can use `--passthrough-first-nic` to attempt to have the VM configured with the pod network (this generates some configuration based on routes, assigned IP address and DNS configuration).

## Quickstart
The helm charts provided assume you have persistent storage working within your cluster. The default StorageClass is cephfs.
Currently the requested PV size is not functional.

```bash
$ git clone https://github.com/lnattrass/docker-qemu-vm.git && cd docker-qemu-vm
$ cd docker-qemu-vm
$ cat <<EOF > ./userdata
#cloud-config
password: ubuntu
chpasswd: { expire: False }
EOF
$ helm template --name=test --set=cpu=1 --set=replicas=2 --set-file userdata=./userdata helm |  kubectl apply -f -
$ kubectl get pods
NAME                           READY   STATUS              RESTARTS   AGE
test-vm-0                   0/1     ContainerCreating   0          3s
$ kubectl logs -f test-vm-0 
$ kubectl exec -it test-vm-0 /vm/console
Press CTRL+O to exit the console

.. you should see ubuntu-18.04 booting ..

Ubuntu 18.04.2 LTS test-vm-0 ttyS0

test-vm-0 login: ubuntu
Password: ubuntu

ubuntu@test-vm-0$ 
<ctrl+O>
$
```

## Options
The following options are available from the entrypoint:
```bash
Usage: entrypoint.py [OPTIONS]

Options:
  --cpu INTEGER            CPU's assigned to the VM
  --ram INTEGER            RAM assigned to the VM (in MB)
  --nic TEXT               Network Cards to Bridge to the VM (can be used
                           multiple times)
  --disk TEXT              Disks to provide to the VM (the first must be the
                           boot disk)
  --image-source TEXT      Image to download as the root disk
  --image-always-pull      Always download the root disk image?
  --immutable              When this machine is shutdown, discard all changes
                           to the disks.
  --passthrough-first-nic  Passthrough the first NIC's IP address from the
                           command line.
  --vm-data DIRECTORY      Path to store VM data
  --config FILE            Persistent VM configuration storage path
  --user-data FILE         Path to user-data
  --debug                  Enable debug logging
  --test                   Don't actually execute the VM
  --help                   Show this message and exit.
```

## Future
Planning to include a metadata service, and the ability to provide secrets/kubernetes service account through to the VM.

