import mysql.connector

def get_connection():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",        
        password="root",   
        database="flask_security_db"  
    )
    return conn
