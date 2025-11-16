# CAN Bridge Pi

This repository turns a Raspberry Pi into a simple **CAN ↔ TCP bridge server**
using `canip_peer.py` and SocketCAN.

Each Pi can expose:

- `can0` → TCP port **3333**
- `can1` → TCP port **3334**
- (room for `can2`/`can3` later: 3335/3336)

The desktop side can then attach via `canip_peer.py client` and treat the
remote CAN buses as local `vcan` interfaces.

> **Note:** This repo bundles `canip_peer.py` and sets up `/home/pi/CAN_IP`
> automatically. No manual CAN_IP setup is required.

---

## Installation (on a Pi)

On the Pi (Raspberry Pi OS or similar):

```bash
sudo apt update
sudo apt install -y python3 iproute2 avahi-daemon git
# can-bridge-pi
