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
