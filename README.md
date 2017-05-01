# go-provision
Provisioning client and mock server in go

Current version uses json over tls; plan is to add grpc APIs.

The overall flow is as follows:
1. Generate a provisioning certificate (7 day lifetime)
   Example:
     server/generate-pc.sh run/nordmark1
   Produces run/nordmark1.*.pem
   
2. Register the provisioning certicate with the mocked up database for
   a user.
   Example:
     server/register-pc erik@zededa.com run/nordmark1.cert.pem
   Add a number as 3rd argument to have it be usable for N devices

Above steps are supposed to be done as part of the user requesting an
image for their device(s) at e.g. developer.zededa.com

3. Start the server on a laptop or server
   Example:
     server/main &
     
4. Log in to device and make it form a self-signed device certificate
   (20 year lifetime)
   Example:
      mkdir /etc/zededa/
      client/generate-dc.sh /etc/zededa/device
   Creates /etc/zededa/device.*.pem

5. Add information from the "image" generation:
      scp somewhere/run/nordmark1.cert.pem /etc/zededa/pc.cert.pem
      scp somewhere/run/nordmark1.key.pem /etc/zededa/pc.key.pem
      scp somewhere/root-certificate.pem /etc/zededa/root-certificate.pem
      echo 'prov01.priv.sc.zededa.net' >/etc/zededa/server

6. Run provisioning client
      client/register /etc/zededa/
      
