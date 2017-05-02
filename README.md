# go-provision
Provisioning client and mock server in go

Current version uses json over tls; plan is to add grpc APIs.

The overall flow is as follows:
1. Generate a provisioning certificate (7 day lifetime)
   Example:
     ./generate-pc.sh /tmp/nordmark
   Produces /tmp/nordmark.*.pem
   
2. Register the provisioning certicate with the mocked up database for
   a user.
   Example:
     ./register erik@zededa.com /tmp/nordmark.cert.pem
   Add a number as 3rd argument to have it be usable for N devices

Above steps are supposed to be done as part of the user requesting an
image for their device(s) at e.g. developer.zededa.com

3. Create server config in /etc/zededa-server containing the following files
   intermediate-ca-chain.pem  server.cert.pem  server.key.pem

4. Start the server on a laptop or server
   Example:
     ./server &
     
5. Log in to device and make it form a self-signed device certificate
   (20 year lifetime)
   Example:
      mkdir /etc/zededa/
      ./generate-dc.sh /etc/zededa/device
   Creates /etc/zededa/device.*.pem

6. Add information from the "image" generation:
      scp somewhere/run/nordmark1.cert.pem /etc/zededa/pc.cert.pem
      scp somewhere/run/nordmark1.key.pem /etc/zededa/pc.key.pem
      scp somewhere/root-certificate.pem /etc/zededa/root-certificate.pem
      echo 'prov01.priv.sc.zededa.net' >/etc/zededa/server

7. Run provisioning client
      ./client /etc/zededa/
      
