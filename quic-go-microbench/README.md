用法：
Linux系统下使用quic-go-microbench/client/client和quic-go-microbench/server/server两个二进制文件，Windows下使用client.exe和server.exe
调用方式：
- client -p 183.173.177.6:8080 -n 1000000 (server地址：端口号，请求包数量)

- server -p 183.173.177.6:8080  

测试信息都打印在标准输出，server需要在测试结束后从外部结束进程