# encrypt-s3

This project provides a simple and secure file upload and download system built using Cloudflare Workers and integrated with any S3 compatible storage provider.

## Features

1. **Encrypt & Upload Files**
   - Upload a file securely to S3 after encryption.
   - Provide the file type and password for encryption.
2. **Download & Decrypt Files**
   - Retrieve a file from S3 and decrypt it using a provided password.
3. **Delete Files**
   - Permanently delete a specific file from S3.

## User Inputs

- **File URL**: URL of the file to be encrypted and uploaded.
- **File Type**: MIME type of the file (e.g., `.pdf`, `.png`).
- **Password**: Custom password used for encryption or decryption.

## Setup and Usage

1. Clone the repository and install dependencies.
2. Configure S3 credentials and bucket details.
3. Run the following commands to setup your local environment:

   ```
   npm install
   npm run dev
   ```

4. Deploy the project.
   ```
   npm run deploy
   ```
# s3chunk
