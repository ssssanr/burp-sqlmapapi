# burp-sqlmapapi

1.burp开启http代理，本地设置，给burp加插件，提取history的请求记录。
2.提取到url信息存储在mysql
3.使用flask读取url信息发送给sqlmapapi去检测注入
