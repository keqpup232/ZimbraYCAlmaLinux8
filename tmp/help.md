### Zimbra install 

sudo dnf -y update
sudo dnf -y install dnf-utils
sudo dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
sudo dnf config-manager --enable powertools
sudo dnf -y install bash-completion vim curl wget unzip openssh-clients telnet net-tools sysstat perl-core libaio nmap-ncat libstdc++.so.6 bind-utils tar
sudo hostnamectl set-hostname mail.keqpup.ru --static
sudo dnf -y install chrony
sudo timedatectl set-timezone Europe/Moscow
sudo systemctl enable --now chronyd
sudo chronyc sources
timedatectl
sudo systemctl reboot

dig A mail.keqpup.ru +short
dig MX keqpup.ru +short
dig MX mail.keqpup.ru +short

sudo localectl set-locale LANG=en_US.UTF-8
sudo localectl set-locale LANGUAGE=en_US
echo "export LC_ALL=en_US.UTF-8" >>~/.bashrc
logout

wget https://files.zimbra.com/downloads/8.8.15_GA/zcs-8.8.15_GA_3953.RHEL8_64.20200629025823.tgz
tar xvf zcs-8.8.15_*.tgz

sudo tee /etc/redhat-release <<EOF
Red Hat Enterprise Linux Server release 8.0 (Ootpa)
EOF

# cat /etc/hosts
127.0.0.1 localhost
51.250.14.14 mail.keqpup.ru mail
192.168.10.13 mail.keqpup.ru mail

cd zcs-8.8.15_*/
sudo ./install.sh

-----------------------------------------------------------
# SSL install

# install certbot then stop zmproxyctl zmmailboxdctl
sudo yum -y install certbot
sudo su - zimbra -c "zmproxyctl stop"
sudo su - zimbra -c "zmmailboxdctl stop"

# first confirm if Zimbra zmhostname value is same as hostname --fqdn value.
sudo su - zimbra -c 'source ~/bin/zmshutil; zmsetvars'
sudo su - zimbra -c 'zmhostname'
sudo su - zimbra -c 'hostname --fqdn'

# check CAA record keqpup.ru. CAA 60	0 issue "letsencrypt.org"
dig $(hostname -d)  caa +short

# Set var
export EMAIL="admin@keqpup.com"
export ZIMBRA_FQDN=$(hostname -f)

# Create cert
sudo certbot certonly --standalone \
  -d $ZIMBRA_FQDN \
  --preferred-chain "ISRG Root X1" \
  --force-renewal \
  --preferred-challenges http \
  --agree-tos \
  -n \
  -m $EMAIL \
  --keep-until-expiring \
  --key-type rsa

# check cert
sudo ls -lh /etc/letsencrypt/live/$ZIMBRA_FQDN

# create /opt/zimbra/ssl/letsencrypt
sudo mkdir /opt/zimbra/ssl/letsencrypt
CERTPATH=/etc/letsencrypt/live/$ZIMBRA_FQDN

# copy file and rename
sudo sh -c 'cp /etc/letsencrypt/archive/mail.keqpup.ru/*.pem /opt/zimbra/ssl/letsencrypt/'
sudo mv /opt/zimbra/ssl/letsencrypt/cert1.pem /opt/zimbra/ssl/letsencrypt/cert.pem
sudo mv /opt/zimbra/ssl/letsencrypt/privkey1.pem /opt/zimbra/ssl/letsencrypt/privkey.pem
sudo mv /opt/zimbra/ssl/letsencrypt/chain1.pem /opt/zimbra/ssl/letsencrypt/chain.pem
sudo mv /opt/zimbra/ssl/letsencrypt/fullchain1.pem /opt/zimbra/ssl/letsencrypt/fullchain.pem

# create and Combine ISRG-X1.pem with zimbra_chain.pem
sudo cat $CERTPATH/chain.pem | sudo tee /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
wget -O /tmp/ISRG-X1.pem https://letsencrypt.org/certs/isrgrootx1.pem.txt
cat /tmp/ISRG-X1.pem | sudo tee -a  /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem

# chown /opt/zimbra/ssl/letsencrypt/
sudo chown -R zimbra:zimbra /opt/zimbra/ssl/letsencrypt/

# verifycrt certs
sudo su - zimbra -c '/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem'

# Backup current certificate files.
sudo cp -a /opt/zimbra/ssl/zimbra /opt/zimbra/ssl/zimbra.$(date "+%Y.%m.%d-%H.%M")

# Copy the private key under Zimbra SSL path.
sudo cp /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/zimbra/commercial/commercial.key
sudo chown zimbra:zimbra /opt/zimbra/ssl/zimbra/commercial/commercial.key

# deploy the new Let’s Encrypt SSL certificate.
sudo su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem'
sudo su - zimbra -c "zmcontrol restart"

-----------------------------------------------------------
## VPN wireguard install

# change dns records / commands are executed locally
yc dns zone replace-records --name zimbra-zone --record "@ 600 MX 0 mx.keqpup.ru"
yc dns zone replace-records --name zimbra-zone --record '@ 600 TXT "v=spf1 a mx ip4:{{ ip_zimbra }} ip4:{{ ip_home }} -all"'
yc dns zone add-records --name zimbra-zone --record "mx 600 A {{ ip_home }}"

# create config for wireguard server and for client
create wg0_server.conf по .j2

wg0_server.conf.j2
[Interface]
Address = 10.13.13.1/24
PrivateKey = AGk7ZGvN6kuvF/2AuCD6ipoPMUzw8XxfRgnP59XQ834=
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth+ -j MASQUERADE
PostUp = iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j DNAT --to-destination {{ ip_zimbra }}:25
PostUp = iptables -t nat -A POSTROUTING -p tcp -d {{ ip_zimbra }} --dport 25 -j MASQUERADE
PostUp = iptables -A FORWARD -p tcp -d {{ ip_zimbra }} --dport 25 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -p tcp --dport 25 ! -d {{ ip_zimbra }} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth+ -j MASQUERADE
PostDown = iptables -t nat -D PREROUTING -i eth0 -p tcp --dport 25 -j DNAT --to-destination {{ ip_zimbra }}:25 || true
PostDown = iptables -t nat -D POSTROUTING -p tcp -d {{ ip_zimbra }} --dport 25 -j MASQUERADE || true
PostDown = iptables -D FORWARD -p tcp -d {{ ip_zimbra }} --dport 25 -j ACCEPT || true
PostDown = iptables -t nat -D POSTROUTING -p tcp --dport 25 ! -d {{ ip_zimbra }} -j MASQUERADE || true
[Peer]
PublicKey = hJsBiwo3eapjK4g54o+UwKXZiPkN4Bh6f+VzFz7es1o=
AllowedIPs = 10.13.13.2/32


create wg0_client.conf по .j2
wg0_client.conf.j2
[Interface]
PrivateKey = UJvoVaOSLhQ4iiC/SWetUjSsBtAYM4m9oPMWzkXxi3s=
Address = 10.13.13.2/24
DNS = 8.8.8.8
PostUp = iptables -t mangle -A OUTPUT -p tcp --dport 25 -j MARK --set-mark 0x1
PostUp = echo "100 vpnroute" >> /etc/iproute2/rt_tables
PostUp = ip rule add fwmark 0x1 table vpnroute
PostUp = ip route add default via 10.13.13.1 dev wg0 table vpnroute
PostUp = ip route add {{ ip_home }}/32 via 192.168.10.1 dev eth0
PostDown = iptables -t mangle -D OUTPUT -p tcp --dport 25 -j MARK --set-mark 0x1
PostDown = ip rule del fwmark 0x1 table vpnroute
PostDown = ip route del default via 10.13.13.1 dev wg0 table vpnroute
PostDown = ip route del {{ ip_home }}/32 via 192.168.10.1 dev eth0
PostDown = sed -i '/vpnroute/d' /etc/iproute2/rt_tables
[Peer]
PublicKey = l+LaTnqowPg1Egh491nLconxL5/aHh3Xxgvd0J9g1hU=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{ ip_home }}:51820
PersistentKeepalive = 25

# running docker locally
mkdir ./config/wg_confs
mv wg0_server.conf ./config/wg_conf/wg0.conf
docker-compose up -d

# connect to zimbra server and set up vpn there
sudo -i
sudo dnf install -y tcpdump
sudo dnf install -y epel-release
sudo dnf install -y wireguard-tools
sudo rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
sudo dnf install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
sudo dnf install -y kmod-wireguard
sudo dnf install -y iptables
mv wg0_client.conf /etc/wireguard/wg0.conf # download config fo server
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

###  help command
tail -f /var/log/zimbra.log
sudo tcpdump -i wg0 -n "port 25"
[root@mail ~]# /opt/zimbra/common/sbin/postsuper -d ALL
postsuper: Deleted: 105 messages
iptables -t nat -L -n -v --line-numbers #посмотреть iptables правила NAT
iptables -L -n -v --line-numbers #посмотреть iptables правила фильтрация 
ip route show default
apk add socat
apk add tcpdump
postqueue -p  # Посмотреть очередь
zmcontrol restart
zmmtactl restart
docker exec -i -t wireguard bash 
wg genkey | tee private.key | wg pubkey > public.key
cat private.key # AGk7ZGvN6kuvF/2AuCD6ipoPMUzw8XxfRgnP59XQ834=
cat public.key # l+LaTnqowPg1Egh491nLconxL5/aHh3Xxgvd0J9g1hU=
docker network prune

---

### **Zimbra Logs & Debugging**
| Command | Description |
|---------|-------------|
| `tail -f /var/log/zimbra.log` | **Live-tail Zimbra logs** (for real-time debugging) |
| `postqueue -p` | **Check mail queue** (lists pending emails) |
| `/opt/zimbra/common/sbin/postsuper -d ALL` | **Delete ALL queued emails** (⚠️ use carefully!) |
| `zmcontrol restart` | **Restart all Zimbra services** |
| `zmmtactl restart` | **Restart Zimbra MTA (Postfix)** |

---

### **Network & VPN Tools**
| Command | Description |
|---------|-------------|
| `sudo tcpdump -i wg0 -n "port 25"` | **Capture SMTP traffic on WireGuard** (`wg0` interface) |
| `ip route show default` | **Show default gateway** (check routing) |
| `iptables -t nat -L -n -v --line-numbers` | **List NAT rules** (with rule numbers) |
| `iptables -L -n -v --line-numbers` | **List firewall rules** (filter table) |
| `apk add socat` | **Install `socat`** (Alpine Linux) |
| `apk add tcpdump` | **Install `tcpdump`** (Alpine Linux) |

---

### **WireGuard VPN**
| Command | Description |
|---------|-------------|
| `wg genkey \| tee private.key \| wg pubkey > public.key` | **Generate WireGuard keys** |
| `cat private.key` | **View private key** (e.g., `AGk7ZGvN6kuvF/2AuCD6ipoPMUzw8XxfRgnP59XQ834=`) |
| `cat public.key` | **View public key** (e.g., `l+LaTnqowPg1Egh491nLconxL5/aHh3Xxgvd0J9g1hU=`) |
| `wg show`         | **Peer handshakes**(last sync time)/**Data transferred**(RX/TX)/**Allowed IPs** (routing) |

---

### **Docker Maintenance**
| Command | Description |
|---------|-------------|
| `docker compose up` | **Start containers** (with `docker-compose.yml`) | Deploy services |
| `docker compose down` | **Stop and remove containers** | Clean up test environments |
| `docker network prune` | **Remove unused Docker networks** (frees up resources) |
| `docker exec -it wireguard bash` | **Enter WireGuard container shell** |
---

