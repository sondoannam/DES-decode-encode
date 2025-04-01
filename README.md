# DES File Encryption System

A modern GUI application for secure file transfer using DES encryption. This system consists of two applications: a sender and a receiver that communicate over a network connection.

## Features

- File encryption using DES algorithm
- Secure file transfer over network
- Modern, user-friendly interface
- Real-time activity logging

## Requirements

- Python 3.6 or higher
- Required Python packages (installed automatically via requirements.txt):
  - numpy
  - tqdm
  - ttkthemes (optional, for improved UI)

## Installation and Setup

### Setting up a Virtual Environment

1. Open a command prompt or terminal
2. Navigate to the project directory:

   ```
   cd d:\documents\CSAT_BMTT\project_27
   ```

3. Create a virtual environment:

   ```
   python -m venv venv
   ```

4. Activate the virtual environment:
   - On Windows:

     ```
     venv\Scripts\activate
     ```

   - On macOS/Linux:

     ```
     source venv/bin/activate
     ```

### Installing Dependencies

1. With the virtual environment activated, install the required packages:

   ```
   pip install -r requirements.txt
   ```

2. For enhanced UI (optional):

   ```
   pip install ttkthemes
   ```

## Running the Application

### Starting the Receiver (Server)

1. With the virtual environment activated, run:

   ```
   python receiver.py
   ```

2. The receiver window will open.
3. Enter an encryption key in hexadecimal format (e.g., `0123456789ABCDEF`).
4. Click "Start Listening" to begin accepting connections.

### Starting the Sender (Client)

1. With the virtual environment activated (in a new terminal), run:

   ```
   python sender.py
   ```

2. The sender window will open.
3. Configure connection settings (default is localhost:8080).
4. Click "Browse" to select a file to encrypt and send.
5. Enter the same encryption key used in the receiver.
6. Click "Send File" to encrypt and send the file.

## Using the Application on a Local Network (LAN)

To use the application between two different computers on the same local network:

### Setting Up the Receiver (Server)

1. Make sure both computers are connected to the same network.
2. On the receiver computer, run the receiver application as described above.
3. The application will display its IP address in the status window. Note this address.
4. If you don't see the IP address, you can find it by:
   - On Windows: Open Command Prompt and type `ipconfig`
   - On macOS/Linux: Open Terminal and type `ifconfig` or `ip addr`
   - Look for IPv4 Address under your active network connection (usually starts with 192.168.x.x or 10.x.x.x)

### Setting Up the Sender (Client)

1. On the sender computer, run the sender application.
2. In the "Server IP" field, enter the IP address of the receiver computer that you noted earlier.
3. Keep the default port (8080) unless you've changed it on the receiver.
4. Select your file, enter the encryption key, and click "Send File".

### Troubleshooting Network Connections

If the sender cannot connect to the receiver:

1. **Firewall Settings**: Make sure the firewall on the receiver computer allows incoming connections on port 8080.
   - On Windows: Open Windows Defender Firewall → Advanced Settings → Inbound Rules → New Rule → Port
   - On macOS: Open System Preferences → Security & Privacy → Firewall → Firewall Options
   - On Linux: Use `sudo ufw allow 8080/tcp` (for Ubuntu/Debian)

2. **Verify Network**: Ensure both computers are on the same network by comparing IP address patterns.

3. **Test Connectivity**: From the sender computer, try to ping the receiver's IP address:
   - Open Command Prompt/Terminal and type `ping [receiver-ip-address]`
   - If ping fails, there might be network isolation or firewall issues

4. **Port Conflicts**: If another application is using port 8080, change the port in both applications.

## Usage Notes

- Both sender and receiver must use the same encryption key.
- The receiver must be started before the sender attempts to connect.
- Encrypted files are saved in a `results` folder as `ReceivedEncode.txt`.
- Decrypted files are saved in a `results` folder as `ReceivedDecode.txt`.

## Troubleshooting

- **Connection errors**: Make sure the receiver is running before the sender attempts to connect.
- **Key errors**: Ensure the encryption key is in the correct hexadecimal format.
- **File not found**: The sender needs read permissions for the selected file.
- **Module not found**: Make sure all dependencies are installed with `pip install -r requirements.txt`.

## Enhancing the Application

- Install `ttkthemes` for a more modern interface: `pip install ttkthemes`.
- You can modify the port number if the default port (8080) is already in use.
