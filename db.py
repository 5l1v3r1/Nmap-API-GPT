import sqlite3

conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
# sql_query = """ CREATE TABLE users(
#     id integer PRIMARY_KEY,
#     username varchar(200) UNIQUE,
#     passwd varchar(200)
# ) """

sql_query="""INSERT INTO users (id, username, passwd) VALUES (1, 'admin' , passwd)"""

cursor.execute(sql_query)
conn.commit()