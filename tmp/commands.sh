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
-----------------------------

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