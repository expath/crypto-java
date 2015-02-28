package ro.kuberam.libs.java.crypto.junit.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Base64Test {

 public static void main(String[] args) {
   BASE64Decoder decoder = new BASE64Decoder();
   BASE64Encoder encoder = new BASE64Encoder();
   try {
     String encodedBytes = encoder.encodeBuffer("JavaTips.net".getBytes());
     System.out.println("encodedBytes " + encodedBytes);
     encodedBytes = 
"-----BEGIN NEW CERTIFICATE REQUEST-----" +
"MIIC1jCCAb4CAQAwgZAxDDAKBgNVBAYTA1VTQTETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UE\n" +
"BxMJQ3VwZXJ0aW5vMRMwEQYDVQQKEwpKb3VybmFsRGV2MQ0wCwYDVQQLEwRKYXZhMTMwMQYDVQQD\n" +
"DCpqb3VybmFsZGV2LmNvbSA8aHR0cDovL3d3dy5qb3VybmFsZGV2LmNvbT4wggEiMA0GCSqGSIb3\n" +
"DQEBAQUAA4IBDwAwggEKAoIBAQCO1uSnJkNYZLBhlE8iBohKnTtTH0S33CPbp/ld5I8/JcPc8EpM\n" +
"VlKAjlYqNrV+UL40IoJKEtHauadu85m+P7WkC/DCMVEYh/SJL5V2qgQaKPVaGLEHutyFx7ZnOyrY\n" +
"z/pvCPLfk5rREitO21nnyBbtCeL83hJld0p0rgaTPPWriDX9lXrHpHS8QAcd8e6Fw8Kxihfmc6w4\n" +
"MqXtxOr38yz4Ny52WdCQL+G4JGitXVxVWBo4l5YE0db0riD9h8TdEMywKDHi8F1Xh1bMHzkq5vmY\n" +
"Mj90gdbvgw8bKSc6e/o9xCO8npXs+Hl9/uKJSRxjDkvy+5zir0C26l2QvHj9xutxAgMBAAGgADAN\n" +
"BgkqhkiG9w0BAQQFAAOCAQEAg5Ez7p0WRBSzjy8Djp6aNgqiBRVfvO6cyNq2t1kWiaW9Dum/AkgT\n" +
"Pi64s7Aiy3LcXMq+rfixRS6Hm7uuREmNEaoHw4F5m6xocg95sM/Xgf3VtlgrbuIhJfzs2fHVQvt4\n" +
"ocwvLmdWCQSBkgm6tAw9DUAxvi+O/8rmVpRC1BwWGuQY3wS5R0GcjzakVrL+HryMUVNfp0h6sSaB\n" +
"X6vWj7vo8WvaPh3skiGN/bGP4KfIVb+V4jVg1aqzpzchijRnHQGoZibSm5GmYjAjfouUCdoaip5r\n" +
"8OhqDOpcoIN3pGstT0lWdGW7x1rnDciWXCfislW8wY4WOlVqZJXY1I0NxJ3t6g==\n" +
"-----END NEW CERTIFICATE REQUEST-----";
     byte[] decodedBytes = decoder.decodeBuffer(encodedBytes);
     Certificate cert = null;
     try {
    	    cert = CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(decodedBytes));
    	}catch(Exception e){
    	    e.printStackTrace();
    	}

     
     
     System.out.println("decodedBytes " + cert.getPublicKey());
   } catch (IOException e) {
     e.printStackTrace();
   }
 }

}
