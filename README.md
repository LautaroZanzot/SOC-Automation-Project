# SOC-Automation-Project

## Objective

The Soc Automation Project aimed to establish a full SOAR solution incorporating Wazuh instance with Source Integration along with functional case managment using TheHive.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Security Automation with Shuffle SOAR
- Incident Respone Planning and Execution
- Case Management with TheHive
- Scripting and Automation for Threar Mitigation

### Tools Used
[Bullet Points - Remove this afterwards]

- Network diagram tools (such as Draw.io)


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
