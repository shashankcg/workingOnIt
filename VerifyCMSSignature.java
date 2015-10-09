//Source: http://stackoverflow.com/questions/16662408/correct-way-to-sign-and-verify-signature-using-bouncycastle

import java.beans.Encoder;
import java.io.FileOutputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;


import sun.misc.BASE64Encoder;

public class VerifySignature {

    public static void main(String[] args) throws Exception {

        /*String envelopedData = "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAAoIAwggLQMIIC" + 
                               "OQIEQ479uzANBgkqhkiG9w0BAQUFADCBrjEmMCQGCSqGSIb3DQEJARYXcm9zZXR0YW5ldEBtZW5k" + 
                               "ZWxzb24uZGUxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIEwZCZXJsaW4xDzANBgNVBAcTBkJlcmxpbjEi" +
                               "MCAGA1UEChMZbWVuZGVsc29uLWUtY29tbWVyY2UgR21iSDEiMCAGA1UECxMZbWVuZGVsc29uLWUt" + 
                               "Y29tbWVyY2UgR21iSDENMAsGA1UEAxMEbWVuZDAeFw0wNTEyMDExMzQyMTlaFw0xOTA4MTAxMzQy" + 
                               "MTlaMIGuMSYwJAYJKoZIhvcNAQkBFhdyb3NldHRhbmV0QG1lbmRlbHNvbi5kZTELMAkGA1UEBhMC" + 
                               "REUxDzANBgNVBAgTBkJlcmxpbjEPMA0GA1UEBxMGQmVybGluMSIwIAYDVQQKExltZW5kZWxzb24t" + 
                               "ZS1jb21tZXJjZSBHbWJIMSIwIAYDVQQLExltZW5kZWxzb24tZS1jb21tZXJjZSBHbWJIMQ0wCwYD" + 
                               "VQQDEwRtZW5kMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+X1g6JvbdwJI6mQMNT41GcycH" + 
                               "UbwCFWKJ4qHDaHffz3n4h+uQJJoQvc8yLTCfnl109GB0yL2Y5YQtTohOS9IwyyMWBhh77WJtCN8r" + 
                               "dOfD2DW17877te+NlpugRvg6eOH6np9Vn3RZODVxxTyyJ8pI8VMnn13YeyMMw7VVaEO5hQIDAQAB" + 
                               "MA0GCSqGSIb3DQEBBQUAA4GBALwOIc/rWMAANdEh/GgO/DSkVMwxM5UBr3TkYbLU/5jg0Lwj3Y++" + 
                               "KhumYSrxnYewSLqK+JXA4Os9NJ+b3eZRZnnYQ9eKeUZgdE/QP9XE04y8WL6ZHLB4sDnmsgVaTU+p" + 
                               "0lFyH0Te9NyPBG0J88109CXKdXCTSN5gq0S1CfYn0staAAAxggG9MIIBuQIBATCBtzCBrjEmMCQG" + 
                               "CSqGSIb3DQEJARYXcm9zZXR0YW5ldEBtZW5kZWxzb24uZGUxCzAJBgNVBAYTAkRFMQ8wDQYDVQQI" + 
                               "EwZCZXJsaW4xDzANBgNVBAcTBkJlcmxpbjEiMCAGA1UEChMZbWVuZGVsc29uLWUtY29tbWVyY2Ug" + 
                               "R21iSDEiMCAGA1UECxMZbWVuZGVsc29uLWUtY29tbWVyY2UgR21iSDENMAsGA1UEAxMEbWVuZAIE" + 
                               "Q479uzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx" + 
                               "DxcNMTMwNTIxMDE1MDUzWjAjBgkqhkiG9w0BCQQxFgQU8mE6gw6iudxLUc9379lWK0lUSWcwDQYJ" + 
                               "KoZIhvcNAQEBBQAEgYB5mVhqJu1iX9nUqfqk7hTYJb1lR/hQiCaxruEuInkuVTglYuyzivZjAR54" + 
                               "zx7Cfm5lkcRyyxQ35ztqoq/V5JzBa+dYkisKcHGptJX3CbmmDIa1s65mEye4eLS4MTBvXCNCUTb9" + 
                               "STYSWvr4VPenN80mbpqSS6JpVxjM0gF3QTAhHwAAAAAAAA==";*/
    	
    	String envelopedData = 
    					"MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggEAjVYC" +
    					"3I1N9qa1t+xUIVHuLrb4QOmStDKPzEGeDXtSIpKan7rfB00PccfW+G1+21gdzsuf7hz3N4S0v6q7" +
    					"hULSLBTreAyY5NMCaE8BwKv9fBWv6uve4CgGdMDtmdu+NRvUaMXuSjrtxwiO2064U9ix1mbBNP+t" +
    					"SSBj0BEzFBgbqOW1jzOguqP9h5VJXDEjUkmIONEebuSXsGYlC35OPGx1OPQTSpcAPCM78BJEEdRf" +
    					"YSp9fKf063tZpveIn2jWXORXvBBMyWx3qGO7iZN4szf8vW7KUybJdzOMT0fKNMNFnEzf7qDnste1" +
    					"WeD1pkrx0rCSqYewhpmmPAXahVP5HjstLAAAAAAAAKCAMIIFfzCCBGegAwIBAgIKEY6T0wAAAAAA" +
    					"YjANBgkqhkiG9w0BAQUFADBvMRMwEQYKCZImiZPyLGQBGRYDY29tMRUwEwYKCZImiZPyLGQBGRYF" +
    					"Y2lzY28xGzAZBgoJkiaJk/IsZAEZFgtpc2VpbmZyYWRldjEkMCIGA1UEAxMbaXNlaW5mcmFkZXYt" +
    					"UE1CVURFVi1BRDAxLUNBMB4XDTE1MDEyNDAzMDU0NFoXDTE2MDEyNDAzMTU0NFowezELMAkGA1UE" +
    					"BhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExETAPBgNVBAcTCFNhbiBKb3NlMRYwFAYDVQQKEw1D" +
    					"aXNjbyBTeXN0ZW1zMQ4wDAYDVQQLEwVTQU1QRzEcMBoGA1UEAxMTc2hhc2MtbG54LmNpc2NvLmNv" +
    					"bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMyWbL4MrBAhool9XYF+fqRqYtT5nWD" +
    					"s7vDk9uE+Ev4No2D0uFtbRSP7gd8/hNOr1XjH3SmjjukIuPbC4GNHa8bBRRNYA+cQ+WgFuuHL1Y9" +
    					"ykudsEFf9QFHOjBZRyzvflS8Rv+gmCGuHudDQyY3Qm/9D1pzuBJWX30iAvbiaA+0SCRfj1kiKHxM" +
    					"axj9IK/IR7dZutFWE5PeesYgAS3hwM5tjRtnDJ5SoLWhvvAUUm/XGhnCLUTtsuorr7JSbA+uK2AT" +
    					"MOlSqBjChOoOkgbgQrjnIkp+XTyu/5RyycsHhFqlNCV/M9RIbhFZPrrhoVzgmt4shSZo+JF7txGh" +
    					"h8hWOhcCAwEAAaOCAg8wggILMB0GA1UdDgQWBBThCH0JXTNzP78vhplOdoNKXKfePzAfBgNVHSME" +
    					"GDAWgBTcm0JpUYKcWvGDJGsqlbPXmwx9oDCB6wYDVR0fBIHjMIHgMIHdoIHaoIHXhoHUbGRhcDov" +
    					"Ly9DTj1pc2VpbmZyYWRldi1QTUJVREVWLUFEMDEtQ0EsQ049cG1idWRldi1hZDAxLENOPUNEUCxD" +
    					"Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERD" +
    					"PWlzZWluZnJhZGV2LERDPWNpc2NvLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jh" +
    					"c2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgdoGCCsGAQUFBwEBBIHNMIHKMIHH" +
    					"BggrBgEFBQcwAoaBumxkYXA6Ly8vQ049aXNlaW5mcmFkZXYtUE1CVURFVi1BRDAxLUNBLENOPUFJ" +
    					"QSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u" +
    					"LERDPWlzZWluZnJhZGV2LERDPWNpc2NvLERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0" +
    					"Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOCAQEAaasxHQsvyXea" +
    					"6IQsgNTADwczSnoDN6uvPqD50wRS0NA85r2TFg45nq7evWxu5aPWAuGgQkPK1JQZiGNClWeP1nw0" +
    					"waR60HgsQu/YlarJiOuQfiJLGdTkYJKH4JB9aUY8OZyKxPSwOWcPcqmA33l6kBUZ+xY51omuWzSe" +
    					"M1eTUlEH3xKQdWaSBhOG3l4B797RvYIApoVTb+UQE99Di0G41fzAQQOfASQUi79oSAdnckJAxabV" +
    					"5X8uOL7sHgx1jjaMyXAWbRP7PGn3KBGK8TobYBZs9YFaL6zCC+Y9BRN+r6Smicy4wledzrxg8rJG" +
    					"EGXBYlSJgKcGp5/Wh1gFux9JzAAAMYICAzCCAf8CAQEwfTBvMRMwEQYKCZImiZPyLGQBGRYDY29t" +
    					"MRUwEwYKCZImiZPyLGQBGRYFY2lzY28xGzAZBgoJkiaJk/IsZAEZFgtpc2VpbmZyYWRldjEkMCIG" +
    					"A1UEAxMbaXNlaW5mcmFkZXYtUE1CVURFVi1BRDAxLUNBAgoRjpPTAAAAAABiMAkGBSsOAwIaBQCg" +
    					"XTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNTA5MjUwMDM3MTha" +
    					"MCMGCSqGSIb3DQEJBDEWBBQ54aMcUE+I42Sy1BWkQdvKMhhuKjANBgkqhkiG9w0BAQEFAASCAQBh" +
    					"xFpSurRXfLMzfrylh7ZqNgD4rhAy26K7hBcvjhU+xNl5AumwkPMVIgaGpXLu4W81Wfk7d0dwl8Ah" +
    					"AYVlT2zcedfTGJgxIK46542B9p57proLrkQo8ql/Y9My2sR25OMIyFYxq0A0QIxySBOQQQHIBgS9" +
    					"QAesZXTd1k/M+baRzg1ObzrPKwcCW0Tf5RAC+S8OVOSZXN62KEnyvnvUW+8EE9YT0D3xxVtthV+y" +
    					"LO20unQv2MWQvfjkWkZg84UR2MT6e2L3WG3960XDae1UrWB+ffEKbd+kUTHsgdxbmzrP3gcTGtWB" +
    					"6GAXuE+pq86Cw+u/B2uHG94dxl0N/PCza3JjAAAAAAAA";
    	
    	String signatureWithSignedData=
    			"MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABBFU" + 
    					"aGlzIGlzIGEgbWVzc2FnZQAAAAAAAKCAMIIFfzCCBGegAwIBAgIKEY6T0wAAAAAAYjANBgkqhkiG" + 
    					"9w0BAQUFADBvMRMwEQYKCZImiZPyLGQBGRYDY29tMRUwEwYKCZImiZPyLGQBGRYFY2lzY28xGzAZ" + 
    					"BgoJkiaJk/IsZAEZFgtpc2VpbmZyYWRldjEkMCIGA1UEAxMbaXNlaW5mcmFkZXYtUE1CVURFVi1B" + 
    					"RDAxLUNBMB4XDTE1MDEyNDAzMDU0NFoXDTE2MDEyNDAzMTU0NFowezELMAkGA1UEBhMCVVMxEzAR" + 
    					"BgNVBAgTCkNhbGlmb3JuaWExETAPBgNVBAcTCFNhbiBKb3NlMRYwFAYDVQQKEw1DaXNjbyBTeXN0" + 
    					"ZW1zMQ4wDAYDVQQLEwVTQU1QRzEcMBoGA1UEAxMTc2hhc2MtbG54LmNpc2NvLmNvbTCCASIwDQYJ" + 
    					"KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMyWbL4MrBAhool9XYF+fqRqYtT5nWDs7vDk9uE+Ev4" + 
    					"No2D0uFtbRSP7gd8/hNOr1XjH3SmjjukIuPbC4GNHa8bBRRNYA+cQ+WgFuuHL1Y9ykudsEFf9QFH" + 
    					"OjBZRyzvflS8Rv+gmCGuHudDQyY3Qm/9D1pzuBJWX30iAvbiaA+0SCRfj1kiKHxMaxj9IK/IR7dZ" + 
    					"utFWE5PeesYgAS3hwM5tjRtnDJ5SoLWhvvAUUm/XGhnCLUTtsuorr7JSbA+uK2ATMOlSqBjChOoO" + 
    					"kgbgQrjnIkp+XTyu/5RyycsHhFqlNCV/M9RIbhFZPrrhoVzgmt4shSZo+JF7txGhh8hWOhcCAwEA" + 
    					"AaOCAg8wggILMB0GA1UdDgQWBBThCH0JXTNzP78vhplOdoNKXKfePzAfBgNVHSMEGDAWgBTcm0Jp" + 
    					"UYKcWvGDJGsqlbPXmwx9oDCB6wYDVR0fBIHjMIHgMIHdoIHaoIHXhoHUbGRhcDovLy9DTj1pc2Vp" + 
    					"bmZyYWRldi1QTUJVREVWLUFEMDEtQ0EsQ049cG1idWRldi1hZDAxLENOPUNEUCxDTj1QdWJsaWMl" + 
    					"MjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWlzZWluZnJh" + 
    					"ZGV2LERDPWNpc2NvLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0" + 
    					"Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgdoGCCsGAQUFBwEBBIHNMIHKMIHHBggrBgEFBQcw" + 
    					"AoaBumxkYXA6Ly8vQ049aXNlaW5mcmFkZXYtUE1CVURFVi1BRDAxLUNBLENOPUFJQSxDTj1QdWJs" + 
    					"aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWlzZWlu" + 
    					"ZnJhZGV2LERDPWNpc2NvLERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2Vy" + 
    					"dGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOCAQEAaasxHQsvyXea6IQsgNTADwcz" + 
    					"SnoDN6uvPqD50wRS0NA85r2TFg45nq7evWxu5aPWAuGgQkPK1JQZiGNClWeP1nw0waR60HgsQu/Y" + 
    					"larJiOuQfiJLGdTkYJKH4JB9aUY8OZyKxPSwOWcPcqmA33l6kBUZ+xY51omuWzSeM1eTUlEH3xKQ" + 
    					"dWaSBhOG3l4B797RvYIApoVTb+UQE99Di0G41fzAQQOfASQUi79oSAdnckJAxabV5X8uOL7sHgx1" + 
    					"jjaMyXAWbRP7PGn3KBGK8TobYBZs9YFaL6zCC+Y9BRN+r6Smicy4wledzrxg8rJGEGXBYlSJgKcG" + 
    					"p5/Wh1gFux9JzAAAMYICEzCCAg8CAQEwfTBvMRMwEQYKCZImiZPyLGQBGRYDY29tMRUwEwYKCZIm" + 
    					"iZPyLGQBGRYFY2lzY28xGzAZBgoJkiaJk/IsZAEZFgtpc2VpbmZyYWRldjEkMCIGA1UEAxMbaXNl" + 
    					"aW5mcmFkZXYtUE1CVURFVi1BRDAxLUNBAgoRjpPTAAAAAABiMA0GCWCGSAFlAwQCAQUAoGkwGAYJ" + 
    					"KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTUwOTI2MDExNDA4WjAvBgkq" + 
    					"hkiG9w0BCQQxIgQgqCbH44nsnzecr9xUTX6aQ5X/e/tYkXu+vuUbPQscmWowDQYJKoZIhvcNAQEB" + 
    					"BQAEggEAcaEXeMIXwGv8PUy2oo8XUoIIiBxDvCt+EgB0sfq9dYTixjdVH0UYNhWbcRTNk5fdtYRk" + 
    					"MQ9c87iMvReeoaqNp5JMaXZbUW4dAu4lw8fumd2YOl5TgCi999ZXb1/ThkRI1W6YYNKwhbU8YB+p" + 
    					"TPwkW2+bvxr1vdXVGfw0cMot9aiZnMSnx4ppgYkmUwQu9WyjrD0aK0tsnGHd4DtishA3WVjrulhN" + 
    					"aEIot34yWDdoC5LErIdSrV2nxIVEDQeCf01OVFMfsM86O84UdTxg1SwxWbnoXpof1mJ95RmPiTYz" + 
    					"ZiwKmRo1lRj3ExBGtOEOyYk6r6DTBE0M3tMBUk320UvNnAAAAAAAAA==";
    	
    	String signeddata = "jVYC3I1N9qa1t+xUIVHuLrb4QOmStDKPzEGeDXtSIpKan7rfB00PccfW+G1+21gdzsuf7hz3N4S0" +
"v6q7hULSLBTreAyY5NMCaE8BwKv9fBWv6uve4CgGdMDtmdu+NRvUaMXuSjrtxwiO2064U9ix1mbB" +
"NP+tSSBj0BEzFBgbqOW1jzOguqP9h5VJXDEjUkmIONEebuSXsGYlC35OPGx1OPQTSpcAPCM78BJE" +
"EdRfYSp9fKf063tZpveIn2jWXORXvBBMyWx3qGO7iZN4szf8vW7KUybJdzOMT0fKNMNFnEzf7qDn" +
"ste1WeD1pkrx0rCSqYewhpmmPAXahVP5HjstLA==";
    	
    	 

        Security.addProvider(new BouncyCastleProvider());

        CMSSignedData cms = new CMSSignedData(Base64.decode(signatureWithSignedData.getBytes()));
        
        //BASE64Encoder encoder = new BASE64Encoder();
        //String signedContent = encoder.encode((byte[]) cms.getSignedContent().getContent());
        //byte[] print = Base64.decode(signedContent.getBytes());
        //String s = new String(print);
        //System.out.println(s);
        //byte[] data = encoder.encode((byte[]) cms.getSignedContent().getContent());
        //String s = new String(cms.getSignedContent().getContent());
        //String s = new String(byte[] cms.getSignedContent().getContent());
        
        //CMSProcessable cmsp = (CMSProcessable) cms.getSignedContent().getContent();

        //cmsp.getContent()
        //CMSEnvelopedDataParser cedp = new CMSEnvelopedDataParser(envelopedData.getBytes());
        //RecipientInformationStore ris =  cedp.getRecipientInfos();
        //Collection enccollection = ris.getRecipients();
        //Iterator it = enccollection.iterator();
        //RecipientInformation re = (RecipientInformation)it.next();
        //byte[] envelData = re.getContent(new X509Certificate)
        
        
        Store store = cms.getCertificates(); 
        SignerInformationStore signers = cms.getSignerInfos(); 
        Collection c = signers.getSigners(); 
        Iterator it = c.iterator();
        while (it.hasNext()) { 
            SignerInformation signer = (SignerInformation) it.next(); 
            Collection certCollection = store.getMatches(signer.getSID()); 
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            //System.out.println(certHolder.getSerialNumber());
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            
            //System.out.println(cert.getSerialNumber() + cert.get);
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
            	
                System.out.println("verified");
                System.out.println(cert.getSerialNumber().toString(16));
                
            }
        }
        byte[] data  = (byte[]) cms.getSignedContent().getContent();
        String str = new String(data);
        System.out.println(str);

    }
