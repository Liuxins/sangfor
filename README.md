### 安装与使用

安装

```bash
go get -u github.com/lyonspdy/sangfor
```

使用

```go
package main

import (
	"fmt"
	"github.com/lyonspdy/sangfor"
)

func main() {
	// secret字段需要在深信服AC上的"开放接口"打开并放通调用方IP后生成
	acSrv := sangfor.NewAC("192.168.1.1:9999", "YR9nQngmvhX&9BE83K")
	version, err := acSrv.GetVersion()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(version)
}
```

### 功能说明

当前只实现了深信服AC的相关API对接,由于API文档中存在太多问题, 导致部分接口无法正常适用,具体请参考代码注释中的 `TODO` 与 `FIXME`部分

状态接口:

- `GetVersion`- 获取版本信息
- `GetOnlineUserCount` - 获取在线用户数
- `GetSessionNum` - 获取当前设备会话数
- `GetInsideLib` - 获取设备内置库版本信息
- `GetLogNum` - 获取日志计数统计(拦截日志,记录日志)
- `GetCpuUsage` - 获取CPU使用率
- `GetMemUsage` - 获取内存使用率
- `GetDiskUsage` - 获取磁盘使用率
- `GetSysTime` - 获取设备的当前系统时间
- `GetThroughput` - 获取设备当前上行和下行流量
- `GetUserRank` - 获取用户流量排行
- `GetAppRank` - 获取应用流量排行
- `GetBandwidthUsage` - 获取带宽利用率

用户接口:

- `UserAdd` - 增加新用户
- `UserDel` - 删除用户 **尚未测试**
- `UserSearch` - 搜索用户
- `UserGet` - 获取一个用户
- `UserPolicySet` - 设置用户的上网策略
- `UserNetPolicyGet` - 获取用户关联的上网策略列表 **参数有误,需联系厂商确认**
- `UserFluxPolicySet` - 设置用户流控策略
- `UserFluxPolicyGet` - 获取用户关联的流控策略列表 **参数有误,需联系厂商确认**
- `UserVerifyPassword` - 校验本地用户密码 **测试失败,实际调用的是获取用户详细信息接口**

在线用户接口:

- `OnlineUserGet` - 获取在线用户列表
- `OnlineUserKick` - 强制注销在线用户
- `OnlineUserUp` - 上线在线用户(单点登录)

组接口:

- `GroupAdd` - 添加组
- `GroupDelete` - 删除组
- `GroupPut` - 修改组信息(只能修改组描述信息)
- `GroupNetPolicySet` - 指定/修改/删除组关联的上网策略
- `GroupNetPolicyGet` - 获取对应组关联的上网策略 **参数有误,需联系厂商确认**

策略接口:

- `PolicyNetGet` - 获取设备已有上网策略信息
- `PolicyFluxGet` - 获取设备已有流控策略信息

绑定相关接口:

- `BindUserSearch` - 查询用户和IP/MAC的绑定关系 **参数有误,需联系厂商确认**
- `BindUserAdd` - 增加用户的IP/MAC绑定 **参数有误,需联系厂商确认**
- `BindUserDel` - 删除用户和IP/MAC的绑定关系 **参数有误,需联系厂商确认**
- `BindIpmacSearch` - 查询IPMac绑定关系
- `BindIpmacAdd` - 增加IP/MAC绑定信息
- `BindIpmacDel` - 删除IP/MAC绑定信息

