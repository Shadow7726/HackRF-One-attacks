# Vulnerabilities in the Z-Wave protocol 

1. **Denial-of-Service via Nonce Get/S2 Nonce Get Manipulation**:
   - *Vulnerability*: Manipulating unencrypted Nonce Get or S2 Nonce Get packets can lead to a denial-of-service attack.
   - *Description*: Altering source and destination addresses to simulate the gateway sending requests to itself causes packet routing overload, leading to gateway overload.

2. **Denial-of-Service via Find Nodes In Range Command Manipulation**:
   - *Vulnerability*: Unencrypted Find Nodes In Range command manipulation leads to a denial-of-service attack.
   - *Description*: Simulating the gateway sending this command to itself causes it to get stuck in a loop sending NOP packets, jamming the network for about 2 minutes.

3. **Gateway as a Central Vulnerability**:
   - *Vulnerability*: The gateway, acting as the central node, becomes a single point of failure.
   - *Description*: Attacking the gateway with denial-of-service attacks can disable the entire Z-Wave network, affecting the functionality of connected devices like alarms and sensors.

4. **Lack of Validation for Packet Addresses**:
   - *Vulnerability*: Insufficient validation for allowed senders or receivers of certain packets.
   - *Description*: Nodes can send Nonce Report packets to non-existent addresses or back to themselves. The gateway fails to validate the authenticity of some requests, like the Find Nodes command.

5. **Response Packet Timing Vulnerability (Older Implementations)**:
   - *Vulnerability*: Earlier Z-Wave protocol versions allowed timing-based follow-up attacks due to Command Complete response packets.
   - *Description*: Sending fake commands would prompt Command Complete packets, enabling attackers to time follow-up attack packets perfectly. Newer versions removed these response packets to mitigate this vulnerability.

.
