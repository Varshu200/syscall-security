# Local web interface

This adds a Flask dashboard for the existing C sandbox. It exposes only fixed demonstration programs: echo, id, hostname, ls, and a fixed timeout demo. It does not accept arbitrary shell commands, executable paths, source uploads, or arbitrary arguments.

## Requirements

Use Kali Linux or another Linux distribution with cgroups v2 and the namespace features required by the original project. Install the existing C dependencies plus Python and Flask.

## Setup

From the repository root:

    sudo apt update
    sudo apt install python3 python3-venv python3-pip build-essential libseccomp-dev busybox-static
    ./setup_rootfs.sh
    make
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt

If root filesystem setup fails while creating /dev/null, run sudo ./setup_rootfs.sh. Run make as your normal user.

## Start the dashboard

Activate the environment if needed, then run:

    sudo .venv/bin/python app.py

Open http://127.0.0.1:5000 in a browser on the same machine. Stop the server with Ctrl+C.

The current sandbox needs root privileges to create cgroups and namespaces, so the dashboard is started with sudo. It binds only to loopback and has an additional loopback request check. Do not change the bind address to 0.0.0.0, port-forward it, or expose it through a public hosting service.

## Troubleshooting

- Sandbox binary not found: run make.
- Root filesystem not found: run ./setup_rootfs.sh (use sudo only if device-node creation requires it).
- cgroup or namespace permission errors: verify cgroups v2 is mounted and that your Linux environment supports the features required by the original sandbox. Some containers and WSL setups do not.
- Flask missing: activate the virtual environment and run pip install -r requirements.txt.

## Security notes

This is a local educational interface, not a production service. The C sandbox shares the host kernel; a web form does not make it a complete security boundary. Keep the program list fixed, review changes to the C sandbox and syscall allowlist, and use a disposable VM for experiments with potentially hostile code. Do not expose this privileged development server to other machines.
