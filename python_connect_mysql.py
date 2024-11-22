import mysql.connector

conn=mysql.connector.connect(host='localhost', username='root', port=3000, password='Vkaps@123456789', database='geekprofile')
my_cursor=conn.cursor()

conn.commit()
conn.close()

print("Connection successfully created!")