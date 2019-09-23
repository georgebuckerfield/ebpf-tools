## Usage

```
make
```
Load the XDP program to the specified device:
```
./xdp_proto_drop_user.o xdp_proto_drop_kern.o <device_name>
```
Update the eBPF map to block specific network protocols e.g.
```
# block icmp
./xdp_proto_drop_cmd.o add 1
```
And to remove the block:
```
./xdp_proto_drop_cmd.o del 1
```
