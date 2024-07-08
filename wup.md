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

![image](https://github.com/j10nelop/m3d1r/assets/152776722/20c05a86-724c-4310-80f3-7c0306452010)

+ bài này ta sẽ download file zip chưa bản update bị lỗ hổng của trang web này

+ unzip file ra ta có rất nhiều file config sau đó ta có thể decomplie file exe bằng cách dùng dotpeek để reverse code

![image](https://github.com/j10nelop/m3d1r/assets/152776722/38198e2a-c615-4dc1-b205-6f9c8e16214c)


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

![image](https://github.com/j10nelop/m3d1r/assets/152776722/c29405f1-201d-4899-b238-63c012932364)

+ add thêm username password ta đặt là admin:admin

nhắc lại dotpeek ta check phân helpfuldesk controller 

![image](https://github.com/j10nelop/m3d1r/assets/152776722/baee7517-9d98-499c-b65f-80634bf9260a)


+ sau đăng nhập vào ta được HOST-WIN-DX130S2

![image](https://github.com/j10nelop/m3d1r/assets/152776722/dc277c6d-a05a-4934-9000-016b7ec22bd6)

=> flag: flag{2fd5d91a4504ecf32a1b701a4b7122db}



**trong bài có sử dụng thêm tool snyk.io**
