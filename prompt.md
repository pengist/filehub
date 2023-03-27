用 Gin 框架实现的一个文件上传下载服务，接口有：

GET /login 登录页面
GET /files 文件列表页面
POST /api/login 登录接口
POST /api/logout 登出接口
GET /api/files 文件列表接口
GET /api/files/:id 下载文件接口
POST /api/files 上传文件接口

注意以下几点： 1.上传文件接口需要支持断点续传； 2.不需要数据库，文件上传后会保存在 ./files 目录下，文件名为文件的 md5，文件的元数据保存在 ./files.json 文件中； 3.不需要有用户，启动服务时在环境变量中设置一个 Key，登录密码由这个 Key 生成基于时间的一次性密码；
4.GET /login 和 GET /files 两个页面请使用 Go embed，方便打包和部署。
