FROM python:3.8

RUN apt update && apt install -y git default-mysql-client

# 安装 python 依赖库
RUN pip install pymysql sqlalchemy

COPY ./teach /opt/teach
COPY ./sqlmap /opt/sqlmap

# 安装dos2unix并转换换行符s
RUN apt-get update && apt-get install -y dos2unix
RUN dos2unix /opt/teach/usesqlmap.py
RUN chmod +x /opt/teach/usesqlmap.py && ln -s /opt/teach/usesqlmap.py /usr/local/bin/usesqlmap

WORKDIR /opt/teach

COPY ./teach/welcome.sh /opt/welcome.sh
RUN chmod +x /opt/welcome.sh
CMD ["bash", "-c", "/opt/welcome.sh"]

RUN ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && chmod +x /opt/sqlmap/sqlmap.py
