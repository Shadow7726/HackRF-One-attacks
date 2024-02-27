## What is IMSI?

The International Mobile Subscriber Identity (IMSI) is a number that uniquely identifies every user of a cellular network. It’s possible with cheap equipment to capture the IMSI numbers nearby.

These IMSI numbers don’t leak names or other data that can link to a person directly. This number does leak information about the operator (MNC) of the number and the operator country (MCC).

**Sample:**  
IMSI:313460000000001  
MCC: 313 = United States  
MNC: 460 = Mobi

In this hands-on tutorial, I’m using the HackRF but it’s also possible with the cheaper RTL-SDR.

## Getting started

**My setup:**
- HackRF (firmware 2023/01)
- VM with Kali(2023)

**Software:**
- GR-GSM
- GsmEvil2
- VirtualBox

Make sure the VM has enough memory and enough CPU available. There are high CPU requirements and if the CPU can’t keep up it will look like it’s not working and won’t return any exceptions.

Not needed but nice to have is the HackRF tools. Install by running this command in Kali:

```bash
sudo apt install hackrf
```

After installation of the HackRF tools, you can find information about the current connected HackRF device with this command.

```bash
sudo hackrf_info
```

**Install GR-GSM**

```bash
sudo apt install gr-gsm
```

Run the scanner to find relevant frequencies. Either use gr-gsm scanner or Kal.

```bash
sudo grgsm_scanner --args=hackrf
```

With kal:

```bash
apt-get install kalibrate-rtl
kal -s GSM900
```

Start monitoring by running “grgsm_livemon”. Use the frequencies found with the previous command.

Example:

```bash
sudo grgsm_livemon -f 947.1M
```

**Install GsmEvil with this command:**

```bash
git clone https://github.com/sharyer/gsmevil2.git
pip3 install -r requirements.txt
cd gsmevil2
```

Run GsmEvil with this command. This command will run a website in the background. After the command is running the website can be accessed by surfing to the localhost.

```bash
python3 GsmEvil.py
```
```

## Troubleshooting

- If the grgsm command doesn’t return an error try appending the “ — debug” parameter to the grgsm command to view more detailed exceptions.
- If no data is received check if the VM has enough CPU and RAM.
