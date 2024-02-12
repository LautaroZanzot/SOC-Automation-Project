# SOC-Automation-Project

## Objective

The Soc Automation Project aimed to establish a full SOAR solution incorporating Wazuh instance with Source Integration along with functional case managment using TheHive.

### Skills Learned

- Security Automation with Shuffle SOAR
- Incident Respone Planning and Execution
- Case Management with TheHive
- Scripting and Automation for Threat Mitigation

### Tools Used

- Network diagram tools (such as Draw.io)
- Virtualization software VirtualBox
- Cloud Virtualization with Azure
- System Monitor for log collection(Sysmon)
- Security Incident Response (TheHive)
- OpenSource NoSQL Database (Cassandra)
- Search and analytics engine (Elasticsearch)
- SOAR (Shuffle)

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

![hive1](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/d7008c5a-1866-4d60-84e0-64d600bb25e9)


Now we can start the service "systemctl start thehive" and then enable it "systemctl enable thehive"

7. Configure Wazuh

To log in Wazuh-Manager we need the admin credentials, for this we found it going to "cd/wazuh-install-files" where we find wazuh-passwords.txt

![wazu](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/7f85bc60-dc5d-47e4-acb5-277380aba09b)

Click on Add agent, select OS system of the new agent (in this case W10), server addres = <PUBLIC_IP> Wazu, and Run the following command on the Windows machine and the start the server.

![wazuhclients](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/30e7636f-04f1-46ad-851c-e54acbb4be78)

At this moment we can query events.

![wazuhagent](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/929ee753-0675-48da-8784-8caeac9218bd)

8. Windows telemetry

Config ossec.conf C:\...\ProgramFiles(x86)\ossec-agent make log analysis with sysmon
<localfile>
   <location>Microsoft-Windows-Sysmon/Operational</location> (operational channel)
   <log_format>syslog</log_format>
</localfile>
Restart Wazu.svc


9. Wazuh Dashboard configuration alert

On Wazuh Machine enable logs alert
nano /var/ossec/etc/ossec.conf
<ossec_config>
   ...
   <logall>no</logall> >> <logall>yes</logall>
Making that wazuh put all logs in /var/ossec/logs/archives/archives/

At this moment we need to enable the filebeat module of archives to make that wazuh can save the logs in archives
nano/etc/filebeat/filebeat.yml
....
filebeat.modules_
   -module: wazuh
   ....
   archives:
      enables: false >> enables: true

Create a new index for archives under wazuh-alerts
Define an index pattern = wazu-archives-**
Timefiled = timestamp

Only logs that trigger the rules will show up, for that we need to configure to show all logs if you want.
For probe this rule we can execute mikmikatz in our W10 Client and grep the archives to see if its triggering.
So execute mimikatz and then in /var/ossec/logs/archives cat archives.json | grep -i mimikatz 
If mimikatz display in the json but isnt in wazuhManager, can be enforced restarting wazuhManager service.
To make a rule to trigger mimikatz we can use the originalFileName, because if we use the image the attaker can change the name and easily bypass the rule 

To create a rule in Wazuh manager > Managment > Rules

![wazuh rules](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/4b15e9e7-51a0-4678-b295-e28e44e98d82)

ManageRules > search "sysmon" > "0800-sysmon_id_1.xml" (id_1 is process creation)
We go here only to make a copy of a rule for our CustomRule

![sysmonrule](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/28049099-6a0c-40aa-81f9-b9635e012f5e)

Go to Custom Rules and edit local_rules.xml
Paste the rule that we copy and modify

![customrule](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/15ae04d1-f76c-40de-8ee3-cd33b122b98e)

Custom rules start in 100000 and the levels of priority are 1 to 15, where 15 has the mayor priority
Save it and restart the manager.

To probe the rule we can change ne name of mimikatz in our w10 client and try to trigger it.

10: Configure Shuffle
Their workflow will be
- Mimikatz Alert Sent to Shuffle
- Shuffle Receives Mimikatz Alert, extract SHA256 hash from file
- Check Reputation Score w/VirusTotal
- Send Detail to TheHive to Create Alert
- Send Email to SOC Analyst to Begin Investigation

Go to the website shuffle.io and create or ouw workflow.
At this moment we start adding our applications, go to triggers and select Webhook and copy the WebhookURI.
Click on Change Me Icon. On Find Actions = Repeat back to me and on Call click on "+" button and selec execution argument.
On wazuhManager machine we need to configure to connect with shuffle
nano /var/ossec/etc/oseec.conf

Under global tag paste the WebhookURI

![webhookinte](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/f8dce093-8f73-4b93-8975-f02625717872)

Keep in mind the identation
Replace hook_url including id and the copy WebhookURI, change the level tag to ruleId tag = <rule_id>10002</rule_id>
Then restart the service and run mimikatz on the client to chekck if its working, will have all te information.

![shuffle](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/b1c361fa-61ec-4c9f-b52b-6bb13a31f6a5)

On Change Me in Find Actions tipe Regex and select Regex capture group and on input data click on "+" button, execution argument and select "hashes". Then in Regex we need to create a regex to parse the sha256 value, so we will use ChatGPT.

![chatgpt](https://github.com/LautaroZanzot/SOC-Automation-Project/assets/33968558/8541086f-ca52-4116-8a1b-16a5584b625d)




