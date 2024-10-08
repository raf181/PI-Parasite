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
