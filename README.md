pcileech-mcp-server

c++ mcp server for pcileech

this lets ai clients like claude use pcileech to do dma stuff - read/write physical memory over pcie hardware.

built with leechcore and vmmdll from ulf frisk's pcileech.

supports fpga devices and whatever hardware pcileech works with.

what it has:
- fast c++ code
- config.json for settings
- memory read/write tools for mcp
- some old win kmd files for legacy crap

need:
- windows x64
- visual studio to build
- pcileech hardware and drivers
- mcp client to connect

how to build:
git clone https://github.com/texas1337/pcileech-mcp-server.git
cd pcileech-mcp-server
open Pcileech.sln in vs and build it (release probably)

config.json looks like:
{
  "pcileech": {
    "device": "fpga",
    "timeout": 30
  },
  "mcp": {
    "name": "pcileech server",
    "version": "0.1"
  }
}

run the exe, hook it up in your ai tool as stdio server.

then you can do stuff like "read 256 bytes from 0x10000 hexdump plz"

files:
src/ - main code
include/ - headers
libs/dlls - deps
nlohmann - json stuff
leechcore.h vmmdll.h - pcileech headers
win7x64.kmd winvistax64.kmd - old kernel things
config.json - config
release/ - built exe

if you wanna add shit, open issue or pr.

thanks ulf frisk for pcileech and nlohmann for json.

thats it
