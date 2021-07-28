# zedUpload

This directory contains functions for uploading and downloading to various remote file storage services, specifically:

* AWS S3
* Azure Blob
* http/s
* sftp

## Testing

In order to run full tests, you need to have a remote account. To run the tests,
set an environment variable for the credentials you need. Those are listed below. If a credential is missing for a test, it simply will not run.

The required environment variables are as follows:

* AWS: `TEST_AWS_BUCKET`, `TEST_AWS_KEY`, `TEST_AWS_SECRET`, `TEST_AWS_REGION`
* Azure: `TEST_AZURE_CONTAINER`, `TEST_AZURE_ACCOUNT_NAME`, `TEST_AZURE_ACCOUNT_KEY`
* http: none are needed, as tests use the public [ptsv2](http://ptsv2.com) for post testing, and [Cirros Cloud](http://download.cirros-cloud.net) and [Ubuntu Images](http://cloud-images.ubuntu.com/) for download testing
* sftp: `TEST_SFTP_DIR`, `TEST_SFTP_USER`, `TEST_SFTP_PASS`, `TEST_SFTP_REGION`
