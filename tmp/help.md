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




sudo dnf -y install bash-completion vim curl wget unzip openssh-clients telnet net-tools sysstat perl-core libaio nmap-ncat libstdc++.so.6 bind-utils tar
sudo timedatectl set-timezone Europe/Moscow
echo ${HOSTNAME}
sudo hostnamectl set-hostname mt.keqpup.ru --static

     - prometheus.yml

sudo useradd -M -r -s /bin/false prometheus
wget https://github.com/prometheus/prometheus/releases/download/v3.4.1/prometheus-3.4.1.linux-amd64.tar.gz
tar xvfz prometheus-3.4.1.linux-amd64.tar.gz
sudo mv prometheus-3.4.1.linux-amd64/prometheus /usr/local/bin/
sudo mv prometheus-3.4.1.linux-amd64/promtool /usr/local/bin/
sudo mkdir -p /var/lib/prometheus/data
sudo chown prometheus:prometheus /var/lib/prometheus/data
sudo mkdir /etc/prometheus/
sudo chown prometheus:prometheus /etc/prometheus/
sudo mv prometheus-3.4.1.linux-amd64/prometheus.yml /etc/prometheus/

# Для бинарников:
sudo chcon -R -t bin_t /usr/local/bin/prometheus
# Для конфигов:
sudo chcon -R -t etc_t /etc/prometheus/
# Для данных:
sudo chcon -R -t var_lib_t /var/lib/prometheus/data/


sudo vim /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target
[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus/data/ \
  --web.listen-address=0.0.0.0:9090
Restart=always
[Install]
WantedBy=multi-user.target

sudo echo "" > /etc/prometheus/prometheus.yml
sudo vim /etc/prometheus/prometheus.yml
# file prometheus.yml

# Для systemd-юнита:
sudo chcon -t systemd_unit_file_t /etc/systemd/system/prometheus.service

sudo vim /etc/prometheus/alert.rules.yml
groups:
- name: example
  rules:
  - alert: HighCpuUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage on {{ $labels.instance }}"
      description: "CPU usage is {{ $value }}%"

sudo systemctl daemon-reload
sudo systemctl start prometheus
sudo systemctl enable prometheus
sudo systemctl status prometheus

sudo systemctl restart prometheus
#  http://mt.keqpup.ru:9090/metrics метрика
#  http://mt.keqpup.ru:9090

     - node_exporter.yml

wget https://github.com/prometheus/node_exporter/releases/download/v1.9.1/node_exporter-1.9.1.linux-amd64.tar.gz
tar xvf node_exporter-1.9.1.linux-amd64.tar.gz
sudo mv node_exporter-1.9.1.linux-amd64/node_exporter /usr/local/bin/


sudo vim /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target
[Service]
User=prometheus
ExecStart=/usr/local/bin/node_exporter
[Install]
WantedBy=multi-user.target

# Для бинарников:
sudo chcon -R -t bin_t /usr/local/bin/node_exporter
# Для systemd-юнита:
sudo chcon -t systemd_unit_file_t /etc/systemd/system/node_exporter.service

sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
sudo systemctl status node_exporter

# http://mt.keqpup.ru:9100/metrics
# http://mt.keqpup.ru:9090/graph

    - alertmanager.yml

wget https://github.com/prometheus/alertmanager/releases/download/v0.28.1/alertmanager-0.28.1.linux-amd64.tar.gz
tar xvf alertmanager-0.28.1.linux-amd64.tar.gz
sudo mv alertmanager-0.28.1.linux-amd64/alertmanager /usr/local/bin/
sudo mv alertmanager-0.28.1.linux-amd64/amtool /usr/local/bin/
sudo mkdir -p /var/lib/alertmanager/data
sudo mkdir -p /etc/alertmanager/
sudo mv alertmanager-0.28.1.linux-amd64/alertmanager.yml /etc/alertmanager/
sudo chown prometheus:prometheus /var/lib/alertmanager/data
sudo chown prometheus:prometheus /etc/alertmanager/


sudo vim /etc/systemd/system/alertmanager.service
[Unit]
Description=Alertmanager
After=network.target
[Service]
User=prometheus
ExecStart=/usr/local/bin/alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/var/lib/alertmanager/data/ \
  --web.listen-address=0.0.0.0:9093
Restart=always
[Install]
WantedBy=multi-user.target

# Для бинарников:
sudo chcon -R -t bin_t /usr/local/bin/alertmanager
# Для конфигов:
sudo chcon -R -t etc_t /etc/alertmanager/
# Для данных:
sudo chcon -R -t var_lib_t /var/lib/alertmanager/data/
# Для systemd-юнита:
sudo chcon -t systemd_unit_file_t /etc/systemd/system/alertmanager.service

sudo echo "" > /etc/alertmanager/alertmanager.yml
sudo vim /etc/alertmanager/alertmanager.yml
route:
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 1h
  receiver: 'telegram'
receivers:
- name: 'telegram'
  telegram_configs:
  - bot_token: 'x'
    chat_id: -x                            
    send_resolved: true                               
    api_url: 'https://api.telegram.org'
    message: '{{ template "telegram.message" . }}'
templates:
- '/etc/alertmanager/telegram.tmpl'
inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']

sudo vim /etc/alertmanager/telegram.tmpl
{{ define "telegram.message" }}
{{- if eq .Status "firing" -}}
🔥 *[{{ .Status | toUpper }}]* {{ .CommonLabels.alertname }}
{{ range .Alerts }}
*Description:* {{ .Annotations.description }}
*Summary:* {{ .Annotations.summary }}
*Severity:* {{ .Labels.severity }}
*Instance:* {{ .Labels.instance }}
*Time:* {{ .StartsAt.Format "2006-01-02 15:04:05" }}
{{- end }}
{{- else -}}
✅ *[{{ .Status | toUpper }}]* {{ .CommonLabels.alertname }}
{{ range .Alerts }}
*Resolved:* {{ .Annotations.summary }}
*Time:* {{ .EndsAt.Format "2006-01-02 15:04:05" }}
*Duration:* {{ .EndsAt.Sub .StartsAt }}
{{- end }}
{{- end }}
{{ end }}

sudo chown prometheus:prometheus /etc/alertmanager/telegram.tmpl
sudo chown -R prometheus:prometheus /var/lib/alertmanager/

sudo systemctl daemon-reload
sudo systemctl start alertmanager
sudo systemctl enable alertmanager
sudo systemctl status alertmanager

# http://mt.keqpup.ru:9093
# test
# sudo dnf install -y stress-ng
# stress-ng --cpu 4 --timeout 7m
# curl -X POST https://api.telegram.org/botx/sendMessage -d "chat_id=-x&text=Test+alert+from+Alertmanager"
# sudo -u prometheus /usr/local/bin/alertmanager   --config.file=/etc/alertmanager/alertmanager.yml   --storage.path=/var/lib/alertmanager/data/   --web.listen-address=0.0.0.0:9093
    

    - grafana.yml

wget https://dl.grafana.com/oss/release/grafana-12.0.1.linux-amd64.tar.gz
tar -zxvf grafana-12.0.1.linux-amd64.tar.gz
sudo useradd -r -s /bin/false grafana
sudo mkdir -p /etc/grafana
sudo mv grafana-v12.0.1/* /etc/grafana
sudo chown -R grafana:users /etc/grafana

sudo vim /etc/systemd/system/grafana-server.service
[Unit]
Description=Grafana Server
After=network.target
[Service]
Type=simple
User=grafana
Group=users
ExecStart=/etc/grafana/bin/grafana server --config=/etc/grafana/conf/defaults.ini --homepath=/etc/grafana
Restart=on-failure
[Install]
WantedBy=multi-user.target

# Для бинарников:
sudo chcon -R -t bin_t /etc/grafana/bin/grafana
sudo chcon -R -t bin_t /etc/grafana/bin/grafana-server
# Для конфигов:
sudo chcon -R -t etc_t /etc/grafana/
# Для данных:
sudo chcon -R -t var_lib_t /etc/grafana/
# Для systemd-юнита:
sudo chcon -t systemd_unit_file_t /etc/systemd/system/grafana-server.service

sudo sed -i 's/^admin_password = admin$/admin_password = qEV*zqm5%5Q~/g' /etc/grafana/conf/defaults.ini
sudo grep "admin_password" /etc/grafana/conf/defaults.ini

sudo systemctl daemon-reload
sudo systemctl start grafana-server
sudo systemctl restart grafana-server
sudo systemctl enable grafana-server
sudo systemctl status grafana-server

# sudo rm -f /etc/grafana/data/grafana.db DB


sudo vim /etc/grafana/conf/provisioning/datasources/prometheus.yml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    editable: false
    jsonData:
      httpMethod: GET
      timeInterval: "15s"
  - name: Alertmanager
    type: alertmanager
    access: proxy
    url: http://localhost:9093
    jsonData:
      implementation: "prometheus"

sudo vim /etc/grafana/conf/provisioning/dashboards/dashboards.yml
apiVersion: 1
providers:
  - name: 'Prometheus Dashboards'
    folder: 'Prometheus'
    type: file
    options:
      path: /etc/grafana/conf/provisioning/dashboards


wget https://raw.githubusercontent.com/rfmoz/grafana-dashboards/refs/heads/master/prometheus/node-exporter-full.json
sudo mv node-exporter-full.json /etc/grafana/conf/provisioning/dashboards
wget https://raw.githubusercontent.com/FUSAKLA/alertmanager-grafana-dashboard/refs/heads/master/dashboard/alertmanager-dashboard.json
sudo mv alertmanager-dashboard.json /etc/grafana/conf/provisioning/dashboards
wget https://raw.githubusercontent.com/jasoncheng7115/zimbra_dashboards/refs/heads/main/Zimbra_Grafana_Prometheus.json
sudo mv Zimbra_Grafana_Prometheus.json /etc/grafana/conf/provisioning/dashboards
wget https://raw.githubusercontent.com/keqpup232/zimbra_dashboards/refs/heads/main/Zimbra%20Dashboard-1638100195495.json
sudo mv 'Zimbra Dashboard-1638100195495.json' /etc/grafana/conf/provisioning/dashboards

sudo vim /etc/grafana/conf/provisioning/dashboards/alertmanager_detail.json
# file alertdetails

sudo systemctl restart grafana-server

    - zimbra_exporter_jasoncheng7115.yml

ansible-playbook -i ./ansible/inventory.ini ./ansible/playbook.yml --tags "zimbra"

sudo -i
pip3 install flask
pip3 install prometheus_client
sudo yum install gcc python3-devel -y
pip3 install psutil

wget https://raw.githubusercontent.com/jasoncheng7115/zimbra_dashboards/main/zimbra_exporter.py -O /opt/zimbra_exporter.py
chmod +x /opt/zimbra_exporter.py

wget https://raw.githubusercontent.com/jmutai/telegraf-ansible/master/templates/zimbra_pflogsumm.pl.j2 -O /opt/zimbra_pflogsumm.pl
chmod +x /opt/zimbra_pflogsumm.pl

# sudo find / -name "zimbra-service*" -type f 2>/dev/null
# sudo ln -s /opt/zimbra/common/bin/pflogsumm.pl /opt/zimbra_pflogsumm.pl
# /opt/zimbra/bin/

sed -i "s/MAILSERVER = 'mail.zimbra.domain'/MAILSERVER = 'mail.keqpup.ru'/" /opt/zimbra_exporter.py
sed -i "s/PORT_EXPORTER = 9093/PORT_EXPORTER = 9095/" /opt/zimbra_exporter.py

wget https://raw.githubusercontent.com/jasoncheng7115/zimbra_dashboards/main/zimbra_exporter.service -O /etc/systemd/system/zimbra_exporter.service

systemctl daemon-reload
systemctl start zimbra_exporter
systemctl enable zimbra_exporter
systemctl status zimbra_exporter

su - zimbra
zmlocalconfig -e zimbra_soap_session_max_idle_time=3600
zmlocalconfig -e zimbra_admin_soap_session_limit=20
zmcontrol restart


    - secure.role

ansible-playbook -i ./ansible/inventory.ini ./ansible/playbook.yml --tags "secure" -e "secure=true"

sudo dnf install -y firewalld
sudo systemctl enable --now firewalld

trusted_networks:
  - 192.168.10.0/24  # Ваша внутренняя сеть
  - 89.169.157.1/32  # IP мониторинга
  - 203.0.113.42/32  # IP зимбры

# Добавление доверительных сетей (пример для домашней сети 192.168.1.0/24 и сервера 203.0.113.5)
sudo firewall-cmd --permanent --new-zone=monitoring
sudo firewall-cmd --permanent --zone=monitoring --add-source=192.168.10.0/24
sudo firewall-cmd --permanent --zone=monitoring --add-service=http
sudo firewall-cmd --permanent --zone=monitoring --add-service=https
sudo firewall-cmd --permanent --zone=monitoring --remove-service=dhcpv6-client

sudo nft insert rule inet firewalld filter_IN_public position 0 tcp dport 9090 reject with tcp reset
sudo firewall-cmd --reload

# Применение правил к сервисам
sudo firewall-cmd --permanent --zone=public --remove-service=http
sudo firewall-cmd --permanent --zone=public --remove-service=https
sudo firewall-cmd --reload
# Проверка
sudo firewall-cmd --zone=monitoring --list-all






# Создание CA (на сервере)
sudo mkdir -p /etc/ssl/{certs,private,ca}
sudo openssl genrsa -out /etc/ssl/private/ca.key 4096
sudo openssl req -x509 -new -nodes -key /etc/ssl/private/ca.key -sha256 -days 3650 -out /etc/ssl/ca/ca.crt -subj "/CN=Monitoring CA"

# Создание серверного сертификата
sudo openssl genrsa -out /etc/ssl/private/mt.keqpup.ru.key 2048
sudo openssl req -new -key /etc/ssl/private/mt.keqpup.ru.key -out /etc/ssl/certs/mt.keqpup.ru.csr -subj "/CN=mt.keqpup.ru"
sudo openssl x509 -req -in /etc/ssl/certs/mt.keqpup.ru.csr -CA /etc/ssl/ca/ca.crt -CAkey /etc/ssl/private/ca.key -CAcreateserial -out /etc/ssl/certs/mt.keqpup.ru.crt -days 365 -sha256

# Создание клиентского сертификата (для домашнего ПК)
openssl genrsa -out ~/monitoring-client.key 2048
openssl req -new -key ~/monitoring-client.key -out ~/monitoring-client.csr -subj "/CN=Home Monitoring Client"
sudo openssl x509 -req -in ~/monitoring-client.csr -CA /etc/ssl/ca/ca.crt -CAkey /etc/ssl/private/ca.key -CAcreateserial -out ~/monitoring-client.crt -days 365 -sha256

# Объединение клиентского сертификата и ключа в PKCS12 (для импорта в браузер)
openssl pkcs12 -export -in ~/monitoring-client.crt -inkey ~/monitoring-client.key -out ~/monitoring-client.p12

# На вашем Mac (в терминале):
scp almalinux@158.160.60.249:~/monitoring-client.p12 ~/Downloads/
scp almalinux@158.160.60.249:/etc/ssl/ca/ca.crt ~/Downloads/

<!--
2. Установка корневого сертификата (CA)
Откройте файл ca.crt двойным кликом
Откроется Keychain Access (Связка ключей)
В диалоговом окне выберите:
Keychain: "System" (для всех пользователей) или "Login" (только для вас)
Нажмите "Add"
Найдите сертификат в списке, кликните правой кнопкой → "Get Info"
В разделе Trust → "When using this certificate" выберите "Always Trust"
3. Установка клиентского сертификата
Откройте файл monitoring-client.p12 двойным кликом
Введите пароль, который вы указали при создании .p12 файла
Выберите Keychain: "Login" (рекомендуется)
Нажмите "Add"
4. Проверка установки
Откройте Keychain Access
В категории "My Certificates" должен быть ваш клиентский сертификат
В категории "Certificates" должен быть корневой сертификат CA
-->




# Установка Nginx
sudo dnf install -y nginx
sudo systemctl enable --now nginx

# Создание базовой аутентификации
sudo dnf install -y httpd-tools
sudo htpasswd -c /etc/nginx/htpasswd admin  # Введите пароль admin

# Настройка виртуального хоста
sudo vim /etc/nginx/conf.d/auth_maps.conf
map $ssl_client_verify $auth_type {
    "SUCCESS"     "off";
    default       "Restricted Area";
}

sudo vim /etc/nginx/conf.d/monitoring.conf
server {
    listen 80;
    server_name mt.keqpup.ru;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name mt.keqpup.ru;
    
    ssl_certificate /etc/ssl/certs/mt.keqpup.ru.crt;
    ssl_certificate_key /etc/ssl/private/mt.keqpup.ru.key;
    ssl_client_certificate /etc/ssl/ca/ca.crt;
    ssl_verify_client optional;
    
    auth_basic $auth_type;
    auth_basic_user_file /etc/nginx/htpasswd;

    location /prometheus/ {
        proxy_pass http://127.0.0.1:9090/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect / /prometheus/;
        proxy_redirect /graph /prometheus/graph;
        proxy_redirect /query /prometheus/query;
        proxy_set_header Accept-Encoding "";
        proxy_http_version 1.1;
        proxy_intercept_errors off;
    }
    
    location /alertmanager/ {
        proxy_pass http://127.0.0.1:9093/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /node-exporter/ {
        proxy_pass http://127.0.0.1:9100/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Проверка конфигурации и перезагрузка
sudo nginx -t
sudo systemctl restart nginx

# Разрешаем Nginx подключаться к сетевым портам
sudo setsebool -P httpd_can_network_connect 1






# Установка EPEL-репозитория
sudo dnf install -y epel-release
# Установка fail2ban
sudo dnf install -y fail2ban
# Включение и запуск службы
sudo systemctl enable --now fail2ban

# Создание конфигурации для Grafana
sudo vim /etc/fail2ban/jail.d/grafana.local
[grafana]
enabled = true
port = http,https
filter = grafana
logpath = /etc/grafana/data/log/grafana.log
maxretry = 3
bantime = 5m
findtime = 2m
banaction = iptables-multiport

sudo rm /etc/fail2ban/filter.d/grafana.conf 
sudo vim /etc/fail2ban/filter.d/grafana.conf
[Definition]
failregex = ^logger=(?:authn\.service|context) .*? remote_addr=<HOST> .*? error="too many consecutive incorrect login attempts for user - login for user temporarily blocked"
            ^logger=authn\.service .*? client=auth\.client\.\w+ .*? remote_addr=<HOST> .*? error="\[password-auth\.failed\] too many consecutive incorrect login attempts for user - login for user temporarily blocked"


# Если контекст неправильный sulinux
sudo semanage fcontext -a -t var_log_t "/etc/grafana/data/log(/.*)?"
sudo restorecon -Rv /etc/grafana/data/log
# Перезапуск fail2ban
sudo systemctl restart fail2ban
sudo systemctl status fail2ban
# Проверка статуса
sudo fail2ban-client status grafana
# Проверка: Сделайте 3 неудачные попытки входа в Grafana в течении 2 минут - ваш IP должен быть заблокирован на 5минут.

sudo journalctl -u zimbra_exporter.service -n 100
tail -f /var/log/zimbra_exporter.log	
sudo systemctl restart zimbra_exporter.service
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365