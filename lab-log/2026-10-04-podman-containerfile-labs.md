# 2026-10-04 · Podman: Containerfile instructions, ports and storage

| | |
| --- | --- |
| **Track** | Containers |
| **Status** | Done |
| **Environment** | Ubuntu 25.10, Podman, run as root |
| **Lab folders** | `redhat_2/add_vs_copy_lab`, `redhat_2/entrypoint-lab`, `redhat_2/EXPOSE-Port-Binding`, `redhat_2/container_vol_and_bind_mounts` (local; not uploaded yet) |

> Backfilled entry. These four labs were done around early October 2026 and are grouped here because the exact day of each was not recorded.

## What the lab covered

A set of short labs on how a Containerfile turns into an image and how a running container talks to the host:

- **ADD vs COPY:** both copy from the build context, but `ADD` also unpacks local tar archives and can fetch URLs. `COPY` is the predictable default.
- **ENTRYPOINT and CMD:** `ENTRYPOINT` fixes the program that runs; `CMD` supplies default arguments that `podman run` can override. A wrapper script can switch behavior based on an environment variable such as `APP_ENV`.
- **EXPOSE and port binding:** `EXPOSE` only documents a port. Traffic reaches the container only when it is published with `-p host:container`.
- **Volumes and bind mounts:** named volumes are managed by Podman; bind mounts map a host directory. Both keep data after the container is removed.

## Commands and configs used

```bash
podman build -t copy-demo -f Dockerfile.copy .
podman build -t add-demo  -f Dockerfile.add  .
podman run --rm add-demo ls -R /app          # compare what each image contains

podman run -d --name web -p 8080:80 <image>  # publish a port
podman port web                              # show the mapping

podman volume create appdata
podman run -d -v appdata:/data <image>       # named volume
podman run -d -v "$PWD/data:/data:Z" <image> # bind mount with SELinux relabel
```

```dockerfile
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["default-argument"]
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| `COPY` build failed | Destination was written with a `~` home-folder path; `~` is a host shell shortcut and means nothing inside an image | Used an absolute container path such as `/app/` |
| `pip` inside `podman build` could not reach pypi.org | Build containers could not resolve DNS on this machine | Workaround: `podman build --network=host`. Root cause not yet diagnosed |

## Key takeaway

Paths in a Containerfile are paths inside the image, not on my laptop. And `EXPOSE` is documentation: nothing is reachable until I publish it with `-p`.

## Screenshots

Not captured for these labs. Fuller notes: [`redhat_2/README.md`](../redhat_2/README.md) once that folder is uploaded.
