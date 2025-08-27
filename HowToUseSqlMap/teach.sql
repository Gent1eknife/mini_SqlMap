CREATE TABLE teachdb.TeachTable (
    id INT AUTO_INCREMENT PRIMARY KEY,
    TeachColumn VARCHAR(255)
);

INSERT INTO teachdb.TeachTable (TeachColumn)
VALUES ('flag{you_know_how_to_use_sqlmap}');

CREATE USER 'teachuser'@'%' IDENTIFIED BY 'teachpass';
GRANT ALL PRIVILEGES ON teachdb.* TO 'teachuser'@'%';
FLUSH PRIVILEGES;
