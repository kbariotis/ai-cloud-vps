# Disposable Ubuntu 24.04 + systemd target that mimics a fresh Hetzner VM after cloud-init.
# Used by `make local-ansible`. Needs --privileged (systemd, nested Docker, ufw/iptables).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv openssh-server sudo python3 iproute2 iptables kmod \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl disable ssh.service \
 && systemctl enable ssh.socket
# ^ like Ubuntu 24.04 cloud images (Hetzner): sshd is socket-activated. Ansible's own SSH
#   login starts ssh.service, which creates /run/sshd, so the missing-directory case is
#   tested separately (local/sshd-regression.yml, run by ansible-test.sh).


# Same shape as cloud-init: key-only sudo user, no root login.
ARG ADMIN_USER=ops
RUN useradd -m -s /bin/bash -G sudo ${ADMIN_USER} \
 && echo "${ADMIN_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-${ADMIN_USER} \
 && install -d -m 700 -o ${ADMIN_USER} -g ${ADMIN_USER} /home/${ADMIN_USER}/.ssh
COPY --chown=${ADMIN_USER}:${ADMIN_USER} --chmod=600 authorized_keys /home/${ADMIN_USER}/.ssh/authorized_keys

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
