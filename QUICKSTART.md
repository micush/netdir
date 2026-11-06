# Quick start

From nothing to an assistant asking your devices, on one node.

## 1. Install

```
tar xzf netdir_v3.tgz && cd netdir
sudo ./install.sh --add-user "$USER"
```

## 2. Try your devices

Before anything goes into the gateway, check that netdir can reach each device. From `source/` on any machine:

```
cp tools/devprobe/lab.json.example lab.json      # set the addresses
export CAT_PASSWORD='…' FGT_TOKEN='…'
go run ./tools/devprobe -inventory lab.json -target all -op facts
```

The README's "Managed devices" section says what each platform needs switched on.

## 3. Configure the gateway

In the web GUI (`https://NODE:22161`, signed in as the user you added): Topology ▸ **＋ New gateway**, then Configure ▸ **Devices** for the devices and their logins, and Configure ▸ **MCP** for who may connect. Monitor ▸ **Devices** ▸ **Ask** checks that every device answers.

Or by hand:

```
sudo cp /usr/local/share/netdir/netdir.conf.example /var/lib/netdir/netdir.conf
sudo chmod 600 /var/lib/netdir/netdir.conf
sudo editor /var/lib/netdir/netdir.conf
```

Set:

- `groups[0].interface` and `vip4`: an unused address on that interface's subnet
- a long random `key`
- your devices and credentials under `settings`
- `settings.mcp_acl` to the address of the machine the assistant runs on (`"10.0.0.20 rw"` to allow changes)

The daemon picks the file up by itself. Check:

```
netdir --show-gateways
netdir --canvas
```

## 4. Connect an assistant

Install a certificate the client trusts (`netdir --tls-install --cert-file F --key-file F`), then, for Claude Code:

```
claude mcp add --transport http netdir https://VIP/mcp
```

Ask it to run `list_devices`, then `device_facts` with target `all`.

## 5. More nodes

On a second node, install it the same way. Then run `netdir --cluster-token` on the first node and `netdir --cluster-join CODE` on the second. The gateway, the devices and the access lists come across, and both nodes answer on the VIP.
