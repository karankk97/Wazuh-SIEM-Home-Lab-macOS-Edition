# Case study · Tracing a Suricata alert into Wazuh

I used a small HTTP response with known content to verify collection. The public test URL I first tried returned a parked-domain page. Hosting the response myself made it clear which bytes crossed the network and why the rule fired.

## Lab configuration

Suricata 8.0.3 runs in AF_PACKET mode on Ubuntu's `enp0s1`. I loaded the rules with `suricata-update`, confirmed signature `2100498` was present, and validated the configuration with `sudo suricata -T -c /etc/suricata/suricata.yaml`. The Ubuntu Wazuh agent reads the following log source inside its existing `<ossec_config>` in `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

After applying this setting, restart the Ubuntu agent with `sudo systemctl restart wazuh-agent` and generate a fresh request.

## Reproduce the test

1. In the **Ubuntu shell** (UTM console or SSH), check the VM's current IPv4 address, create the harmless response, and start the temporary server. Leave it running for the next step.

   ```bash
   ip -br -4 addr show enp0s1
   mkdir -p /tmp/suricata-test
   printf 'uid=0(root) gid=0(root) groups=0(root)\n' > /tmp/suricata-test/index.html
   python3 -m http.server 8000 --bind 0.0.0.0 --directory /tmp/suricata-test
   ```

2. In a **separate macOS Terminal** on the M4, replace `VM_IP` with the address above, omitting its subnet suffix. Use plain HTTP so the sensor can inspect the test text.

   ```bash
   curl --max-time 10 http://VM_IP:8000/
   ```

3. Confirm that curl prints the test text and that the server recorded a successful request. Press **Ctrl+C** in the Ubuntu server terminal. In that same Ubuntu shell, check the latest matching EVE alerts:

   ```bash
   sudo jq -c 'select(.event_type=="alert" and .alert.signature_id==2100498) | {timestamp,src_ip,dest_ip,signature:.alert.signature}' /var/log/suricata/eve.json | tail -3
   ```

4. In **Wazuh → Threat Hunting → Events**, select a time window covering the new request. Search for `agent.name:"ubuntu-suricata" AND rule.id:"86601"`. Expand the GPL event and compare the signature ID, endpoints, and time with the local record. Multiple Suricata signatures can share this Wazuh rule.

**Finding.** The Python server on the VM sent the matching response to the Mac. The signature ID identifies the bytes Suricata detected, while the Wazuh rule ID identifies how the manager classified the incoming alert. The expected HTTP contents and server banner explain both detections in this test.

[Local Suricata evidence](suricata-eve-alerts.png) · [Wazuh dashboard evidence](ubuntu-threat-hunting.png) · [Return to the lab overview](../README.md)
