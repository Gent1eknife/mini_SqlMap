#!/bin/bash
clear
cat << "EOF"

    __  __                ______        __  __            _____         __ __  ___            
   / / / /____  _      __/_  __/____   / / / /_____ ___  / ___/ ____ _ / //  |/  /____ _ ____ 
  / /_/ // __ \| | /| / / / /  / __ \ / / / // ___// _ \ \__ \ / __ `// // /|_/ // __ `// __ \
 / __  // /_/ /| |/ |/ / / /  / /_/ // /_/ /(__  )/  __/___/ // /_/ // // /  / // /_/ // /_/ /
/_/ /_/ \____/ |__/|__/ /_/   \____/ \____//____/ \___//____/ \__, //_//_/  /_/ \__,_// .___/ 
                                                                /_/                  /_/      

echo "👋 欢迎使用 SQLMap 教学版！"
echo ""
echo "你的目标：使用 SQLMap 从数据库中注出 flag。"
echo "数据库信息如下："
echo "  主机：sqlmap_mysql"
echo "  用户：root"
echo "  密码：root"
echo "  数据库：teachdb"
echo ""
echo "👉 步骤一：进入 sqlmap 文件夹："
echo "    cd /opt/sqlmap"
echo ""
echo "👉 步骤二：尝试连接数据库（测试用）"
echo "    python3 sqlmap.py -d "mysql://teachuser:teachpass@sqlmap_mysql:3306/teachdb" --tables
"
echo ""
echo "👉 步骤三：注出表 teachdb.TeachTable 的数据"
echo "    python3 sqlmap.py -d 'mysql://root:root@sqlmap_mysql/teachdb' -T TeachTable --dump"
echo ""
echo "📚 教程文档：/opt/teach/lesson1.md"
exec bash
