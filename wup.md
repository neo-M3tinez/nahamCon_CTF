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
