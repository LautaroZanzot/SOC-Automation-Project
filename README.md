# SOC-Automation-Project

## Objective

The Soc Automation Project aimed to establish a full SOAR solution incorporating Wazuh instance with Source Integration along with functional case managment using TheHive.

### Skills Learned

- Security Automation with Shuffle SOAR
- Incident Respone Planning and Execution
- Case Management with TheHive
- Scripting and Automation for Threar Mitigation

### Tools Used

- Network diagram tools (such as Draw.io)
- Virtualization software VirtualBox
- Cloud Virtualization with Azure
- System Monitor for log collection(Sysmon)
- Security Incident Response (TheHive)


## Steps

### Step 1 - Desing a diagram

![1nd Workflow](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/3a9ece4c-3067-4724-8da8-6d501daea77f)

*Network Diagram*

This diagram have 8 events
1. Wazuh Agent send Events to Wazuh Manager throught Internet (Green link = Send & Receive Events over Wazuh Manager)
2. Wazuh Manager receive events sent for Wazuh Agent
3. Wazuh Manager eventually would create an alert and send it to Shuffle (Red link = Send Alerts)
4. Enrich IOCS and send it back to shuffle
5. Shuffle send alert to TheHive
6. Shuffle send email to SOC Analyst containing details of the alert (Grey link= Send and Receive email) 
7. SOC Analyst send response action over Shuffle, then over Wazuh Manager, and finally to Windows Client to perform that action
8. Windows Client perfome response action


![Workflow, no diagram](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/c4d24b1a-71de-46fc-93a8-d61e5a0a8b6f)

*Workflow*

### Step 2 - Install Components

Start making the Network

1. Virtualize Windows10 with VirtualBox
2. Install Sysmon
![w10 client](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/41dee46d-babd-47b9-92f7-7e5c2547dcd1)

3. Install Wazuh

curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

Extract Wazuh Credentials
sudo tar -xvf wazuh-install-files.tar

![Wazuh Install](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/a001d855-c199-4bc9-a530-cc2738633978)
![WazuhManager](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/9eb68cc8-7a97-4ea8-b7da-bbd7a72566a2)

4. Install TheHive dependences

Dependences
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release

Install Java
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

Install Cassandra
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra

Install ElasticSearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch

***OPTIONAL ELASTICSEARCH***
Create a jvm.options file under /etc/elasticsearch/jvm.options.d and put the following configurations in that file.
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g

5. Install TheHive

wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive

Default Credentials on port 9000
credentials are 'admin@thehive.local' with a password of 'secret'

6. Configure TheHive

Configure Cassandra
nano /etc/cassandra/cassandra.yaml
cluster_name: 'Test Cluster' >> 'SocProject' #Optional
listen_addres: localhost >> <PUBLIC_IP> TheHive
rpc_adres: localhost >> <PUBLIC_IP> TheHive
seed_provider:
   - class_name: org.apache.cassandra.locator.SimpleSeedProvider
     parameters:
        - seeds: "127.0.0.1:7000" >> <PUBLIC_IP>:7000 TheHive
Stop cassandra service, delete old files rm -rf /var/lib/cassandra/*
Start cassandra service

Configure elasticsearch
nano /etc/elasticsearch/elasticsearch.yml
#cluster.name : my-application >> cluster.name: thehive
#node.name: node-1 >> node.name: node-1
#network.host: 192.168.0.1 >> network.host: <PUBLIC_IP> TheHive
#http.port: 9200 >> http.port: 9200
#cluster.initial_master_nodes: ["node-1","node-2"] >> cluster.initial_master_nodes: ["node-1"]

Now we can start the service "systemctl start elasticsearch" and then enable it "systemctl enable elasticsearch"

At this moment we start configuring TheHive
First of all, we have to change the permissions of the hive in /opt/thp "chown -R thehive:thehive /opt/thp"
Now we can configure thehhive applicattion conf
nano /etc/thehive/application.conf
db.janusgraph
   hostname = ["127.0.0.1"] >>> <PUBLIC_IP> TheHive
   cluster-name = thp >> SocProject
index.seach
   hostname = ["127.0.0.1"] >>> <PUBLIC_IP> TheHive
application.baseUrl = "http://localhost:9000" >>> <PUBLIC_IP>:9000 TheHive

Now we can start the service "systemctl start thehive" and then enable it "systemctl enable thehive"


