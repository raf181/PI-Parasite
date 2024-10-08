#!/bin/bash
# PI-Parasite Automated Setup Script
# This script configures the Raspberry Pi Zero 2W for persistent network access using Ethernet and WiFi with ZeroTier.

set -e

# Function to prompt the user for input with default values
prompt_user_input() {
    local var_name=$1
    local prompt_message=$2
    local default_value=$3
    read -p "${prompt_message} [${default_value}]: " input
    if [[ -z "$input" ]]; then
        eval "$var_name=\"$default_value\""
    else
        eval "$var_name=\"$input\""
    fi
}

# Prompting the user for configuration variables
echo "Welcome to the PI-Parasite Automated Setup Script!"
echo "Please provide the following configuration details."

# 1. Hostname Prefix
prompt_user_input HOSTNAME_PREFIX "Enter Hostname Prefix (e.g., DESKTOP)" "DESKTOP"

# 2. ZeroTier Network ID
prompt_user_input ZEROTIER_NETWORK_ID "Enter your ZeroTier Network ID" "YOUR_ZEROTIER_NETWORK_ID"

# 3. WiFi AP SSID
prompt_user_input WIFI_AP_SSID "Enter WiFi Access Point SSID" "PI-Parasite-AP"

# 4. WiFi AP Password
while true; do
    read -s -p "Enter WiFi Access Point Password (minimum 8 characters): " WIFI_AP_PASSWORD
    echo
    if [[ ${#WIFI_AP_PASSWORD} -ge 8 ]]; then
        break
    else
        echo "Password must be at least 8 characters long. Please try again."
    fi
done

# Display the collected configuration
echo ""
echo "Configuration Summary:"
echo "Hostname Prefix       : ${HOSTNAME_PREFIX}"
echo "ZeroTier Network ID   : ${ZEROTIER_NETWORK_ID}"
echo "WiFi AP SSID          : ${WIFI_AP_SSID}"
echo "WiFi AP Password      : ${WIFI_AP_PASSWORD}"
echo ""

# Confirm to proceed
read -p "Do you want to proceed with the setup? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Setup aborted by user."
    exit 1
fi

# Variables
SCRIPT_DIR="/opt/pi-parasite"

# Function to update and upgrade the system
update_system() {
    echo "Updating and upgrading the system..."
    sudo apt update && sudo apt upgrade -y
}

# Function to install required packages
install_packages() {
    echo "Installing required packages..."
    sudo apt install -y curl ufw hostapd dnsmasq lighttpd python3 python3-flask python3-venv git
}

# Function to configure hostname
configure_hostname() {
    echo "Configuring hostname to mimic Windows device..."
    RANDOM_SUFFIX=$(openssl rand -hex 3 | tr '[:lower:]' '[:upper:]')
    NEW_HOSTNAME="${HOSTNAME_PREFIX}-${RANDOM_SUFFIX}"
    sudo hostnamectl set-hostname "${NEW_HOSTNAME}"
    sudo sed -i "s/127.0.1.1.*/127.0.1.1 ${NEW_HOSTNAME}/" /etc/hosts
    echo "Hostname set to ${NEW_HOSTNAME}"
}

# Function to configure firewall (UFW)
configure_firewall() {
    echo "Configuring UFW firewall..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw allow 9993/udp  # ZeroTier default port
    sudo ufw --force enable
    echo "Firewall configured to allow only SSH and ZeroTier traffic."
}

# Function to install and configure ZeroTier
install_zerotier() {
    echo "Installing ZeroTier..."
    curl -s https://install.zerotier.com | sudo bash
    sudo systemctl enable zerotier-one
    sudo systemctl start zerotier-one
    sudo zerotier-cli join "${ZEROTIER_NETWORK_ID}"
    echo "ZeroTier installed and joined network ${ZEROTIER_NETWORK_ID}."
    echo "Please authorize the Pi in your ZeroTier Central dashboard."
    echo "Press Enter to continue after authorization..."
    read
}

# Function to generate and configure SSH keys
configure_ssh() {
    echo "Configuring SSH with key-based authentication..."
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo systemctl restart ssh

    # Create .ssh directory and set permissions
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh

    # Prompt user to paste their public SSH key
    echo "Please paste your public SSH key below and press Enter:"
    read -p "SSH Public Key: " SSH_PUB_KEY
    echo "${SSH_PUB_KEY}" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo "SSH key added."
}

# Function to disable unnecessary services
disable_services() {
    echo "Disabling unnecessary services..."
    sudo systemctl disable --now bluetooth.service
    sudo systemctl disable --now avahi-daemon.service
    echo "Unnecessary services disabled."
}

# Function to set up network interfaces
configure_network() {
    echo "Configuring network priorities..."
    sudo bash -c 'cat >> /etc/dhcpcd.conf <<EOL

interface eth0
    metric 100

interface wlan0
    metric 200
EOL'
    sudo systemctl restart dhcpcd
    echo "Network priorities set: Ethernet > WiFi."
}

# Function to set up Access Point (AP) mode
setup_ap_mode() {
    echo "Setting up Access Point (AP) mode..."
    
    # Configure static IP for wlan0
    sudo bash -c 'cat >> /etc/dhcpcd.conf <<EOL

interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
EOL'
    
    # Configure hostapd
    sudo bash -c 'cat > /etc/hostapd/hostapd.conf <<EOL
interface=wlan0
driver=nl80211
ssid='"${WIFI_AP_SSID}"'
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase='"${WIFI_AP_PASSWORD}"'
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOL'
    
    sudo sed -i 's|#DAEMON_CONF=""|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
    
    # Configure dnsmasq
    sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
    sudo bash -c 'cat > /etc/dnsmasq.conf <<EOL
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
EOL'
    
    # Enable IP forwarding
    sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sudo sysctl -p
    
    # Configure iptables for NAT
    sudo bash -c 'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'
    sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
    sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"
    
    # Restore iptables on boot
    sudo bash -c 'cat >> /etc/rc.local <<EOL
iptables-restore < /etc/iptables.ipv4.nat
exit 0
EOL'
    
    # Enable and start services
    sudo systemctl unmask hostapd
    sudo systemctl enable hostapd
    sudo systemctl enable dnsmasq
    sudo systemctl start hostapd
    sudo systemctl start dnsmasq
    
    echo "Access Point (AP) mode configured."
}

# Function to set up web dashboard for WiFi configuration
setup_web_dashboard() {
    echo "Setting up web dashboard for WiFi configuration..."
    
    # Create project directory
    sudo mkdir -p "${SCRIPT_DIR}"
    sudo chown -R pi:pi "${SCRIPT_DIR}"
    
    # Create Python virtual environment
    sudo -u pi bash -c "python3 -m venv ${SCRIPT_DIR}/venv"
    sudo -u pi bash -c "source ${SCRIPT_DIR}/venv/bin/activate && pip install flask"
    
    # Create Flask app
    sudo -u pi bash -c "cat > ${SCRIPT_DIR}/app.py <<EOL
from flask import Flask, request, render_template, redirect, url_for
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        ssid = request.form['ssid']
        password = request.form['password']
        update_wifi(ssid, password)
        return redirect(url_for('success'))
    return render_template('index.html')

@app.route('/success')
def success():
    return "WiFi configuration updated successfully! The Pi will reboot and connect to the new network."

def update_wifi(ssid, password):
    wifi_conf = f'''
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={{
    ssid="{ssid}"
    psk="{password}"
    key_mgmt=WPA-PSK
}}
'''
    with open('/etc/wpa_supplicant/wpa_supplicant.conf', 'w') as f:
        f.write(wifi_conf)
    os.system('sudo wpa_cli -i wlan0 reconfigure')
    os.system('sudo reboot')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
EOL"
    
    # Create HTML template
    sudo -u pi mkdir -p "${SCRIPT_DIR}/templates"
    sudo -u pi bash -c "cat > ${SCRIPT_DIR}/templates/index.html <<EOL
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Configuration</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 300px; margin: auto; padding-top: 100px; }
        input[type=text], input[type=password] {
            width: 100%;
            padding: 12px 20px;
            margin: 8px 0;
            box-sizing: border-box;
        }
        input[type=submit] {
            width: 100%;
            background-color: #4CAF50;
            color: white;
            padding: 14px 20px;
            margin: 8px 0;
            border: none;
            cursor: pointer;
        }
        input[type=submit]:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Configure WiFi</h2>
        <form method="post">
            <label for="ssid">SSID:</label>
            <input type="text" id="ssid" name="ssid" required>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>

            <input type="submit" value="Submit">
        </form>
    </div>
</body>
</html>
EOL"
    
    # Create systemd service for Flask app
    sudo bash -c "cat > /etc/systemd/system/wifi-config.service <<EOL
[Unit]
Description=WiFi Configuration Flask App
After=network.target

[Service]
User=pi
WorkingDirectory=${SCRIPT_DIR}
Environment=\"PATH=${SCRIPT_DIR}/venv/bin\"
ExecStart=${SCRIPT_DIR}/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL"
    
    # Enable and start the Flask service
    sudo systemctl daemon-reload
    sudo systemctl enable wifi-config.service
    sudo systemctl start wifi-config.service
    
    # Configure Lighttpd to proxy to Flask app
    sudo bash -c 'cat > /etc/lighttpd/conf-available/15-proxy.conf <<EOL
server.modules += ( "mod_proxy" )

$HTTP["url"] =~ "^/.*$" {
    proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => 80 ) ) )
}
EOL'
    
    sudo lighty-enable-mod proxy
    sudo lighty-enable-mod proxy_fcgi
    sudo lighty-enable-mod fastcgi
    sudo lighty-enable-mod setenv
    sudo systemctl restart lighttpd
    
    echo "Web dashboard for WiFi configuration set up."
}

# Function to create startup script for network check
create_startup_script() {
    echo "Creating startup script for network check..."
    
    sudo bash -c 'cat > /usr/local/bin/network-check.sh <<EOL
#!/bin/bash

# Check for Ethernet connection
if ip link show eth0 | grep "state UP" > /dev/null; then
    echo "Ethernet is connected. Ensuring network services are active."
    sudo systemctl enable zerotier-one
    sudo systemctl start zerotier-one
    sudo systemctl disable hostapd
    sudo systemctl disable dnsmasq
    sudo systemctl stop hostapd
    sudo systemctl stop dnsmasq
else
    echo "Ethernet is not connected. Enabling Access Point mode."
    sudo systemctl enable hostapd
    sudo systemctl enable dnsmasq
    sudo systemctl start hostapd
    sudo systemctl start dnsmasq
    sudo systemctl disable zerotier-one
    sudo systemctl stop zerotier-one
fi
EOL'
    
    sudo chmod +x /usr/local/bin/network-check.sh
    
    # Create systemd service to run the script at boot
    sudo bash -c 'cat > /etc/systemd/system/network-check.service <<EOL
[Unit]
Description=Network Check Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/network-check.sh

[Install]
WantedBy=multi-user.target
EOL'
    
    sudo systemctl daemon-reload
    sudo systemctl enable network-check.service
    echo "Startup network check script created and enabled."
}

# Function to set up persistent WiFi configuration
setup_persistent_wifi() {
    echo "Setting up persistent WiFi configuration..."
    
    # Ensure wpa_supplicant is properly configured
    sudo bash -c 'cat > /etc/wpa_supplicant/wpa_supplicant.conf <<EOL
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

# WiFi networks will be added here
EOL'
    
    echo "Persistent WiFi configuration set."
}

# Main Execution
echo "Starting PI-Parasite automated setup..."

update_system
install_packages
configure_hostname
configure_firewall
disable_services
configure_network
setup_ap_mode
setup_web_dashboard
install_zerotier
configure_ssh
create_startup_script
setup_persistent_wifi

echo "PI-Parasite setup complete! Rebooting now..."
sudo reboot
