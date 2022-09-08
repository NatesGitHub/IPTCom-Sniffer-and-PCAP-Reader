A program to format captured (Bombardier) IPTCom TCMS signals sniffed using Scapy and analyzed with Wireshark. 

Captured TCP packets are reversed engineered through theoretical pattern observation and testing. Packets are dissected and formatted based on the raw decrypted 'header' information for each packet frame, which are then able to be separated and assigned to their relative payload information headers. Header and signal information are logged into text files as a buffer to be transmitted to a SQL server when an access point is established.
